
#define _GNU_SOURCE
#include "caps/live_internal.h"
#include "util/gostr.h"
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int lv_close_checked(int fd)
{
	if (fd >= 0 && close(fd))
		return -errno;
	return 0;
}

int lv_unknownf(char **msg, const char *fmt, ...)
{
 va_list ap;va_start(ap,fmt);char *why=NULL;
 int n=vasprintf(&why,fmt,ap);va_end(ap);
 if(n<0)return BML_Q_ERROR;
 n=asprintf(msg,"%s: cannot be determined on this target",why);free(why);
 return n<0?BML_Q_ERROR:BML_Q_UNKNOWN;
}

int lv_memo_answer(const struct lv_memo *m, int *out, char **msg)
{
 *out=m->value;*msg=m->msg?strdup(m->msg):NULL;
 return m->msg && !*msg?BML_Q_ERROR:m->rc;
}

void lv_btf_reason(struct lv_res *r,int load_error,const char *log,size_t size)
{
 if(!load_error){char *e=bml_go_errno_str(r->err);
  if(e)asprintf(&r->text,"detect support for BTF: %s",e);
  free(e);return;
 }
 struct lv_res tmp={.err=r->err,.verifier=1};
 if(log)lv_log_lines(log,size,&tmp.lines,&tmp.n_lines);
 char *text=lv_res_text(&tmp);
 if(text && strncmp(text,"load program: ",14)==0)asprintf(&r->text,"load btf: %s",text+14);
 free(text);lv_res_free(&tmp);
}

int lv_memo_reason(struct bml_live *l,const char *key,int rc,int value,char *why,int *out,char **msg)
{
 if(lv_memo_put(l,key,rc,value)!=0){free(why);*msg=strdup("out of memory");return BML_Q_ERROR;}
 struct lv_memo *m=&l->memo[l->n_memo-1];m->msg=why;
 return lv_memo_answer(m,out,msg);
}
