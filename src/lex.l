/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms
 *
 * Scanner for the GssapiRequiredNameAttributes option parser.
 */
%{
#include <string.h>
#include "parser.h"
%}

%option noyywrap noinput nounput

%%

"(" { return LPAREN; }
")" { return RPAREN; }
" " { return SPACE; }
"or" { return OR; }
"OR" { return OR; }
"and" { return AND; }
"AND" { return AND; }
"=" { return EQUAL; }
":=" { return EQUALBIN; }
"*" { return AST; }
[A-Za-z0-9_\-\[\]]+ {
	yylval.sval = strdup(yytext);
	return STRING;
}

%%
