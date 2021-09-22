#include <security/pam_modules.h>

/* --- authentication management functions --- */

#define UNUSED

int
pam_sm_authenticate(pam_handle_t *pamh UNUSED, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* --- account management functions --- */

int
pam_sm_acct_mgmt(pam_handle_t *pamh UNUSED, int flags UNUSED,
		 int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* --- password management --- */

int
pam_sm_chauthtok(pam_handle_t *pamh UNUSED, int flags UNUSED,
		 int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* --- session management --- */

int
pam_sm_open_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

int
pam_sm_close_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* end of module definition */
