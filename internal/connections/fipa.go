package connections

import "jwt-auth/internal/auth"

var LdapConnetion *auth.ClientLdap
var IpaConnetion *auth.ClientIPA

func IPAClient() {
	connLdap, _ := auth.NewLdapClient()
	connIpa, _ := auth.NewIpaClient()

	LdapConnetion = connLdap
	IpaConnetion = connIpa
}
