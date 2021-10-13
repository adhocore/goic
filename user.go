package goic

// User represents user from well know user info endpoint
type User struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Name          string `json:"name"`
	Picture       string `json:"picture,omitempty"`
	Subject       string `json:"sub,omitempty"`
	Error         error  `json:"-"`
}

// withError embeds Error to User
func (u *User) withError(err error) *User {
	u.Error = err
	return u
}
