







#include "bml-precheck/precheck.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bml/bml.h"
#include "caps/recorded.h"
#include "json/json.h"
#include "req/from_elf.h"


static struct out o;
static struct bml_loader_decl file_decl;
static struct bml_recorded *rec;
static struct bml_requirements *req;
static char *elf_data;
static size_t elf_len;
static struct bml_live_caps live;
static struct bml_caps under;
static struct bml_recorder *recorder;

static int run(int argc, char **argv)
{

	struct flags f = {.hint = "rebuild both ELF and caller from the same schema"};
	struct bml_buf ferr = {0};
	if (pc_parse_flags(argc, argv, &f, &ferr)) {
		int rc = pc_usage(&o, ferr.p);
		bml_buf_free(&ferr);
		return rc;
	}

	if ((f.debug_root_set || f.n_debug) && (!f.live || f.caps))
		return pc_usage(&o, "--debug / --debug-root are for --live alone (a record names its debug files)");
	if (f.version)
		return pc_emit(&o, "version", EXIT_OK_);


	const struct bml_loader_decl *decl;
	if (f.loader && f.loader_file)
		return pc_usage(&o, "give either --loader or --loader-file, not both");
	if (f.loader) {
		decl = bml_loader_preset(f.loader);
		if (!decl) {
			struct bml_buf m = {0};
			bml_buf_adds(&m, "unknown loader preset ");
			bml_buf_add_goquote(&m, f.loader, strlen(f.loader));
			bml_buf_addf(&m, " (known: %s)", BML_LOADER_PRESETS);
			int rc = pc_usage(&o, m.p);
			bml_buf_free(&m);
			return rc;
		}
	} else if (f.loader_file) {
		char *e = NULL;
		if (pc_load_loader_file(f.loader_file, &file_decl, &e)) {
			int rc = pc_usage(&o, e);
			free(e);
			return rc;
		}
		decl = &file_decl;
	} else {
		return pc_usage(&o, "no loader declaration (--loader=<preset> or --loader-file=<decl.json>) — the check depends on how the loader behaves and is not run without it");
	}
	o.loader = decl;


	long long luid;
	char *lcap = NULL;
	pc_run_as(&luid, &lcap);
	if (f.load_as) {
		long long u;
		char *c = NULL, *le = NULL;
		if (bml_caps_parse_load_as(f.load_as, &u, &c, &le)) {
			int rc = pc_usage(&o, le ? le : "out of memory");
			free(le);
			free(lcap);
			return rc;
		}
		if (f.live && !bml_caps_same_privilege(c, lcap)) {
			struct bml_buf m = {0};
			bml_buf_addf(&m, "--load-as %s differs from this process (cap_eff %s): a live probe answers for this process's privilege — run ebpf-precheck as the loading process",
				     f.load_as, lcap ? lcap : "");
			int rc = pc_usage(&o, m.p);
			bml_buf_free(&m);
			free(c);
			free(lcap);
			return rc;
		}
		if (!f.caps) {
			free(c);
			free(lcap);
			return pc_usage(&o, "--load-as is for --caps (a live probe is this process)");
		}
		free(lcap);
		luid = u, lcap = c;
	}
	o.load_uid = luid;
	o.load_cap = lcap;
	if (!f.live && !f.caps)
		return pc_usage(&o, "give --live, --caps, or both (--caps --live re-probes the privilege-dependent queries live when the record's privilege differs)");
	if (f.live && f.caps && (f.n_binary || f.n_ext_target))
		return pc_usage(&o, "--binary / --ext-target are for --live alone (with --caps the record answers the binaries and replacement targets)");
	char *e = NULL;
	struct bml_caps caps, reprobe;
	if (f.live && !f.caps) {
		char *le = pc_open_live(&f, decl, &live, &caps);
		if (le) {
			int rc = pc_usage(&o, le);
			free(le);
			return rc;
		}
		o.has_probed_as = 1;
		pc_run_as(&o.probed_uid, &o.probed_cap);
	} else {
		if (f.n_binary)
			return pc_usage(&o, "--binary is for --live (a record names its binaries)");
		if (f.n_ext_target)
			return pc_usage(&o, "--ext-target is for --live (a record does not carry replacement targets)");
		rec = bml_recorded_read(f.caps, &e);
		if (!rec) {
			int rc = pc_usage(&o, e);
			free(e);
			return rc;
		}
		bml_recorded_caps(rec, &caps);
	}
	const struct bml_loader_decl *rdecl = caps.loader(caps.ctx);
	if (f.caps && !pc_decl_equal(rdecl, decl)) {
		struct bml_buf m = {0};
		bml_buf_addf(&m, "the record %s was made for loader ", f.caps);
		bml_buf_add_goquote(&m, rdecl->name, strlen(rdecl->name));
		bml_buf_adds(&m, ", not the declared ");
		bml_buf_add_goquote(&m, decl->name, strlen(decl->name));
		bml_buf_adds(&m, " — judge with the record's loader or record again");
		int rc = pc_usage(&o, m.p);
		bml_buf_free(&m);
		return rc;
	}
	if (f.caps && bml_recorded_probed_as(rec, &o.probed_uid, &o.probed_cap))
		o.has_probed_as = 1;
	if (f.caps) {
		const struct bml_caps *rp = NULL;
		if (f.live) {
			char *le = pc_open_live(&f, decl, &live, &reprobe);
			if (le) {
				int rc = pc_usage(&o, le);
				free(le);
				return rc;
			}
			rp = &reprobe;
			o.reprobed = !o.has_probed_as || !bml_caps_same_privilege(o.probed_cap, o.load_cap);
		}
		if (bml_recorded_for_load(rec, o.load_uid, o.load_cap, rp))
			return pc_usage(&o, "out of memory");
		o.has_load_as = 1;
	}
	if (f.record) {
		under = caps;
		recorder = bml_recorder_new(&under);
		if (!recorder)
			return pc_usage(&o, "out of memory");
		for (int i = 0; i < f.n_binary; i++) {
			const char *eq = strchr(f.binary[i], '=');
			char *prog = eq ? strndup(f.binary[i], (size_t)(eq - f.binary[i])) : NULL;
			int bad = !eq || !prog || bml_recorder_set_binary(recorder, prog, eq + 1);
			free(prog);
			if (bad)
				return pc_usage(&o, "out of memory");
		}
		bml_recorder_caps(recorder, &caps);
	}



	size_t len;
	char *data;
	if (f.requirements && f.n_args == 0) {
		data = pc_read_file(f.requirements, &len, &e);
		if (!data) {
			int rc = pc_usage(&o, e);
			free(e);
			return rc;
		}
		if (bml_req_parse(data, len, &req, &o.pe)) {
			bml_requirements_free(req);
			req = NULL;
			o.has_err = 1;
			bml_buf_adds(&o.err, "cannot read requirements: ");
			bml_buf_adds(&o.err, o.pe.msg ? o.pe.msg : "");
			o.has_parse_error = o.pe.rule[0] != 0;
			free(data);
			return pc_emit(&o, "requirements_invalid", EXIT_INVALID);
		}
	} else if (!f.requirements && f.n_args == 1) {
		data = pc_read_file(f.args[0], &len, &e);
		if (!data) {
			int rc = pc_usage(&o, e);
			free(e);
			return rc;
		}
		struct bml_req_elf_error ee;
		if (bml_req_from_elf(data, len, &req, &ee)) {
			o.has_err = 1;
			bml_buf_adds(&o.err, "cannot read requirements from the embedded ELF: ");
			if (ee.stage == BML_REQ_ELF_PARSE) {
				bml_buf_adds(&o.err, ee.parse.msg ? ee.parse.msg : "");
				o.pe = ee.parse;
				o.has_parse_error = ee.parse.rule[0] != 0;
				free(ee.msg);
			} else {
				bml_buf_adds(&o.err, ee.msg ? ee.msg : "");
				bml_req_elf_error_free(&ee);
			}
			free(data);
			return pc_emit(&o, "requirements_invalid", EXIT_INVALID);
		}
	} else {
		return pc_usage(&o, "give one object file or --requirements");
	}
	if (!f.requirements) {
		elf_data = data;
		elf_len = len;
	} else {
		free(data);
	}
	o.object_format = req->version;

	if (f.schema && f.schema[0] && strcmp(req->schema_sha256.p ? req->schema_sha256.p : "", f.schema) != 0) {
		o.has_err = 1;
		bml_buf_adds(&o.err, "ELF was built from schema ");
		const char *es = req->schema_sha256.p ? req->schema_sha256.p : "";
		bml_buf_add_goquote(&o.err, es, strlen(es));
		bml_buf_adds(&o.err, ", bindings from schema ");
		bml_buf_add_goquote(&o.err, f.schema, strlen(f.schema));
		bml_buf_adds(&o.err, " — ");
		bml_buf_adds(&o.err, f.hint);
		return pc_emit(&o, "schema_mismatch", EXIT_SCHEMA);
	}

	if (f.maps) {
		size_t ml;
		char *me = NULL;
		char *mj = pc_read_file(f.maps, &ml, &me);
		if (!mj) {
			int rc = pc_usage(&o, me);
			free(me);
			return rc;
		}
		struct bml_map_decls md;
		char *de = NULL;
		int prc = bml_map_decls_parse(mj, ml, &md, &de);
		free(mj);
		if (prc) {
			struct bml_buf m = {0};
			bml_buf_addf(&m, "maps file %s: %s", f.maps, de ? de : "");
			free(de);
			int rc = pc_usage(&o, m.p);
			bml_buf_free(&m);
			return rc;
		}
		int mrc = bml_check_map_decls(req, elf_data, elf_len, &md, &o.mp);
		bml_map_decls_free(&md);
		if (mrc < 0)
			return pc_usage(&o, "out of memory");
		if (mrc > 0) {
			o.has_err = 1;
			bml_buf_adds(&o.err, "the map declarations differ from the ELF (regenerate the bindings from the same schema):");
			for (size_t i = 0; i < o.mp.n; i++) {
				char *s = bml_map_problem_string(&o.mp.p[i]);
				bml_buf_adds(&o.err, "\n  ");
				bml_buf_adds(&o.err, s ? s : "");
				free(s);
			}
			return pc_emit(&o, "map_mismatch", EXIT_MAPS);
		}
	}

	char *cerr = NULL;
	int crc = bml_check(req, &caps, &o.unmet, &cerr);
	if (recorder) {
		long long uid;
		char *cap = NULL;
		if (o.has_load_as) {
			uid = o.load_uid;
			cap = strdup(o.load_cap ? o.load_cap : "");
		} else if (o.has_probed_as) {
			uid = o.probed_uid;
			cap = strdup(o.probed_cap ? o.probed_cap : "");
		} else
			pc_run_as(&uid, &cap);
		char *we = pc_write_record(recorder, f.record, uid, cap ? cap : "", decl);
		free(cap);
		if (we) {
			free(cerr);
			int rc = pc_usage(&o, we);
			free(we);
			return rc;
		}
	}
	if (crc) {
		o.has_err = 1;
		bml_buf_adds(&o.err, cerr);
		free(cerr);
		return pc_emit(&o, "precheck_failed", EXIT_PRECHECK);
	}
	int blocking = 0;
	for (size_t i = 0; i < o.unmet.n; i++)
		blocking |= bml_unmet_blocks_load(&o.unmet.u[i]);
	int rc = blocking ? pc_emit(&o, "target_rejected", EXIT_REJECTED) : pc_emit(&o, "ok", EXIT_OK_);





	return rc;
}

int main(int argc, char **argv)
{
	int rc = run(argc, argv);
	bml_unmets_free(&o.unmet);
	bml_requirements_free(req);
	free(elf_data);
	bml_map_problems_free(&o.mp);
	bml_recorded_free(rec);
	bml_recorder_free(recorder);
	bml_live_caps_free(&live);
	bml_loader_decl_free(&file_decl);
	free(o.probed_cap);
	free(o.load_cap);
	bml_buf_free(&o.err);
	bml_parse_error_free(&o.pe);
	return rc;
}
