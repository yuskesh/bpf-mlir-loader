
#ifndef BML_CAPS_VALUE_SOURCES_H
#define BML_CAPS_VALUE_SOURCES_H

#include "caps/live.h"

struct lv_module_name { char *name; uint32_t kind; };
struct lv_value_module { char *name; struct lv_module_name *types; size_t count; };
struct bml_kernel_sources {
	int modules_done, modules_failed;
	char *module_error;
	struct lv_value_module *modules;
	size_t count;
	int config_done, config_failed;
	char *config_error;
	struct bml_kv *config;
	size_t config_count;
};
struct bml_kernel_sources *lv_value_sources(struct bml_live *l);
void lv_value_sources_free(struct bml_live *l);
int lv_value_read(const char *path, uint8_t **out, size_t *len, char **err);
void lv_value_modules(struct bml_live *l, struct bml_kernel_sources *s);
int lv_value_absent(struct bml_kernel_sources *s, const char *what, const char *name, uint32_t kind, const char *sentinel, char **msg);

#endif
