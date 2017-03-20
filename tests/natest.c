/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms
 *
 * Unit tests for the GssapiRequiredNameAttributes option parser.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/mag_parse.h"

void usage(char *name)
{
    fprintf(stderr, "%s \"expr\" [\"attr=val\", ...]\n", name);
    exit(-1);
}

int main(int argc, char **argv)
{
    int ret;
    int anum = 0;
    const char **attrs = NULL;
    const char **vals = NULL;

    if (argc < 3)
        usage(argv[0]);

    ret = mag_check_name_attr_expr(argv[1]);
    if (ret != 1) {
        fprintf(stderr, "syntax error\n");
        exit(1);
    }

    attrs = calloc(argc - 1, sizeof(*attrs));
    vals = calloc(argc - 1, sizeof(*vals));

    if (attrs == NULL || vals == NULL) {
        fprintf(stderr, "calloc failed\n");
        exit(1);
    }

    for (int i = 2; i < argc; i++) {
        char *v, *a = argv[i];

        v = strchr(a, '=');
        if (v == NULL)
            continue;

        *v++ = '\0';
        if (*v == '\0')
            continue;

        attrs[anum] = a;
        vals[anum++] = v;
    }
    ret = mag_verify_name_attributes(argv[1], attrs, vals);
    if (ret == 1) {
        fprintf(stdout, "True\n");
        ret = 0;
    } else {
        fprintf(stdout, "False\n");
        ret = 1;
    }

    exit(ret);
}
