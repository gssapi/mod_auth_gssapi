/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms
 *
 * Bison file for the GssapiRequiredNameAttributes option parser.
 *
 * Rule := (RequiredKV | "(" Rule ")"),  { ' ', (AND|OR), ' ', Rule } ;
 * RequiredKV := (Key, "=", Value) | (Key, ":=" BinValue) ;
 * Key := <string> ;
 * Value := <string> | '*' ;
 * BinValue := <base64> ;
 * AND := "and" | "AND" ;
 * OR := "or" | "OR" ;
 *
 */
%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <apr_base64.h>
int yylex(void);
typedef struct yy_buffer_state * YY_BUFFER_STATE;
extern void yyerror(const char **keys, const char **vals,
                    int *status, const char *s);
extern int yyparse(const char **keys, const char **vals, int *status);
extern YY_BUFFER_STATE yy_scan_string(char * str);
extern void yy_delete_buffer(YY_BUFFER_STATE buffer);
static size_t b64_len(const char *val);
static char *b64_enc(const char *val, size_t len);
%}

%union {
    char *sval;
    int ival;
}

%token LPAREN
%token RPAREN
%token SPACE
%token OR
%token AND
%token EQUAL
%token EQUALBIN
%token AST
%token STRING
%token INT

%type <sval> STRING
%type <ival> INT rule rule_start requiredkv

%parse-param {const char **keys} {const char **vals} {int *status}

%%

expr: rule {
      if (status != NULL)
          *status = $1;
    }
    ;

rule: rule_start
    | rule_start SPACE AND SPACE rule {
      $$ = $1 && $5;
    }
    | rule_start SPACE OR SPACE rule {
      $$ = $1 || $5;
    }
    ;

rule_start: LPAREN rule RPAREN {
            $$ = $2;
          }
          | requiredkv {
            $$ = $1;
          }
          ;

requiredkv: STRING EQUAL STRING {
            int ret = 0;
            size_t sz;
            if (keys != NULL && vals != NULL) {
                for (int i = 0; keys[i] != NULL && vals[i] != NULL; i++) {
                    if (strcmp($1, keys[i]) != 0) {
                        continue;
                    }
                    sz = 0;
                    memcpy(&sz, vals[i], sizeof(sz));
                    if (sz == 0) {
                        continue;
                    }
                    if (!memcmp($3, vals[i] + sizeof(sz), sz)) {
                        ret = 1;
                        break;
                    }
                }
            }
            $$ = ret;
          }
          | STRING EQUAL AST {
            int ret = 0;
            if (keys != NULL && vals != NULL) {
                for (int i = 0; keys[i] != NULL && vals[i] != NULL; i++) {
                    if (strcmp($1, keys[i]) == 0) {
                       ret = 1;
                       break;
                    }
                }
            }
            $$ = ret;
          }
          | STRING EQUALBIN STRING {
            int ret = 0;
            if (keys != NULL && vals != NULL) {
                for (int i = 0; keys[i] != NULL && vals[i] != NULL; i++) {
                    if (strcmp($1, keys[i]) != 0) {
                        continue;
                    }
                    size_t b64len = b64_len(vals[i]);
                    /* b64len includes the NULL terminator. */
                    if (strlen($3) + 1 != b64len) {
                        continue;
                    }
                    char *b64val = b64_enc(vals[i], b64len);
                    if (!b64val) {
                        continue;
                    }
                    if (strcmp($3, b64val) == 0) {
                        ret = 1;
                    }
                    free(b64val);
                    if (ret) {
                        break;
                    }
                }
            }
            $$ = ret;
          }
          ;

%%

static size_t b64_len(const char *val)
{
    size_t sz = 0;

    memcpy(&sz, val, sizeof(sz));
    if (sz == 0)
        return sz;

    return apr_base64_encode_len(sz);
}

static char *b64_enc(const char *val, size_t len)
{
    size_t sz = 0;
    char *b64val;

    memcpy(&sz, val, sizeof(sz));
    if (sz == 0)
        return NULL;

    b64val = calloc(1, len + 1);
    if (!b64val)
        return NULL;

    apr_base64_encode(b64val, val + sizeof(sz), sz);
    return b64val;
}

/* Return 1 if the given name attributes and values (NULL terminated arrays)
 * satisfy the expression.  This does not handle parsing errors from yyparse,
 * so expr should be checked by required_name_attr_expr_check() first. */
int mag_verify_name_attributes(const char *expr, const char **attrs,
                               const char **vals)
{
    int ret = 0, status = 0;
    YY_BUFFER_STATE buffer;

    /* No name attribute requirements. Pass. */
    if (expr == NULL) {
        return 1;
    }

    /* No name attributes but required attributes are specified. Fail. */
    if (attrs == NULL || vals == NULL ||
        attrs[0] == NULL || vals[0] == NULL) {
        return 0;
    }

    buffer = yy_scan_string((char *)expr);
    ret = yyparse(attrs, vals, &status);
    yy_delete_buffer(buffer);

    return ret == 0 && status;
}

/* Return 1 if the expression is provided and valid, else return 0. */
int mag_check_name_attr_expr(const char *expr)
{
    int ret;
    YY_BUFFER_STATE buffer = yy_scan_string((char *)expr);

    /* Just verify the syntax. */
    ret = yyparse(NULL, NULL, NULL);
    yy_delete_buffer(buffer);

    return ret == 0;
}

/* Define a no-op yyerror().  Syntax errors are logged outside of calling
 * required_name_attr_expr_check(). */
void yyerror(const char **keys, const char **vals, int *status, const char *s)
{
    return;
}
