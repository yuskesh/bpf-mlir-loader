#include "maps/internal.h"
#include "maps/arena.h"
int bml_map_decls_parse(const char *p,size_t n,struct bml_map_decls *d,char **e)
{return md_map_decls_parse(p,n,d,e,NULL,0);}
int bml_map_decls_parse_rule(const char *p,size_t n,struct bml_map_decls *d,char **e,enum bml_json_rule *r)
{return md_map_decls_parse(p,n,d,e,r,0);}
int bml_map_decl_parse_one(const char *p,size_t n,struct bml_map_decl *d,char **e)
{return md_map_decl_parse_one(p,n,d,e,0);}
int bml_arena_map_decls_parse(const char *p,size_t n,struct bml_map_decls *d,char **e)
{return md_map_decls_parse(p,n,d,e,NULL,1);}
int bml_arena_map_decl_parse_one(const char *p,size_t n,struct bml_map_decl *d,char **e)
{return md_map_decl_parse_one(p,n,d,e,1);}
