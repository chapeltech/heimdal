/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "krb5_locl.h"
#include <err.h>

/*
 * Test run functions, to be used with valgrind to detect memoryleaks.
 */

struct log_state {
    int called;
    int closed;
};

static void KRB5_CALLCONV
log_func(const char *prefix, const char *msg, void *data)
{
    struct log_state *state = data;

    if (prefix == NULL || strcmp(msg, "compat callback") != 0)
	errx(1, "bad log callback arguments");
    state->called++;
}

static void KRB5_CALLCONV
close_func(void *data)
{
    struct log_state *state = data;

    state->closed++;
}

static void
check_log(void)
{
    struct krb5_log_facility_v7 {
	char *program;
	int len;
	void *val;
    };
    int i;

    if (sizeof(krb5_log_facility) != sizeof(struct krb5_log_facility_v7) ||
	offsetof(krb5_log_facility, program) !=
	    offsetof(struct krb5_log_facility_v7, program) ||
	offsetof(krb5_log_facility, len) !=
	    offsetof(struct krb5_log_facility_v7, len) ||
	offsetof(krb5_log_facility, val) !=
	    offsetof(struct krb5_log_facility_v7, val))
	errx(1, "krb5_log_facility layout changed");

    for (i = 0; i < 10; i++) {
	struct log_state state = { 0, 0 };
	krb5_log_facility *logfacility;
	krb5_context context;
	krb5_error_code ret;

	ret = krb5_init_context(&context);
	if (ret)
	    errx (1, "krb5_init_context failed: %d", ret);

	krb5_initlog(context, "test-mem", &logfacility);
	krb5_addlog_dest(context, logfacility, "0/STDERR:");
	krb5_addlog_func(context, logfacility, 0, -1,
			 log_func, close_func, &state);
	krb5_set_warn_dest(context, logfacility);
	if (strcmp(logfacility->program, "test-mem") != 0 ||
	    logfacility->len != 2 ||
	    krb5_get_warn_dest(context) != logfacility)
	    errx(1, "bad log facility state");
	krb5_log(context, logfacility, 0, "compat callback");

	krb5_free_context(context);
	if (state.called != 1 || state.closed != 1)
	    errx(1, "log callback not called or closed");
    }
}


int
main(int argc, char **argv)
{
    setprogname(argv[0]);

    check_log();

    return 0;
}
