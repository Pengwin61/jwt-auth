package auth

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ccin2p3/go-freeipa/freeipa"
)

type ClientIPA struct {
	con *freeipa.Client
}

func NewIpaClient() (*ClientIPA, error) {

	conn, err := ConIpa()

	if err != nil {
		return nil, err
	}
	return &ClientIPA{con: conn}, nil
}

func ConIpa() (*freeipa.Client, error) {

	tspt := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c, err := freeipa.Connect(os.Getenv("IPA_HOST"), tspt, os.Getenv("IPA_USER"), os.Getenv("IPA_PASSWORD"))
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ClientIPA) CheckUser(username string) (*string, bool, error) {
	var isAdmin bool

	res, err := c.con.UserShow(&freeipa.UserShowArgs{}, &freeipa.UserShowOptionalArgs{UID: freeipa.String(username)})

	if err != nil {
		if ipaE, ok := err.(*freeipa.Error); ok {
			log.Printf("FreeIPA error %v: %v\n", ipaE.Code, ipaE.Message)
			if ipaE.Code == freeipa.NotFoundCode {
				log.Println("(matched expected error code)")
			}
		} else {
			log.Printf("Other error: %v", err)
		}
		return nil, false, err
	}

	userGroups := res.Result.MemberofGroup

	for _, group := range *userGroups {
		isAdmin = strings.Contains(group, "admins")
	}

	return &res.Result.UID, isAdmin, err
}
