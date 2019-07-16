package v1

//LoginInfo JSON body to request login
type LoginInfo struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

//RegisterInfo JSON body to request register
type RegisterInfo struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}
