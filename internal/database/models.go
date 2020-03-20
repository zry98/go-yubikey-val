package database

type Client struct {
	Id        int32  `db:"id"`
	Active    bool   `db:"active"`
	CreatedAt int32  `db:"created"`
	Secret    string `db:"secret"`
	Email     string `db:"email"`
	Notes     string `db:"notes"`
	Otp       string `db:"otp"`
}

type YubiKey struct {
	Active         bool   `db:"active"`
	CreatedAt      int32  `db:"created"`
	ModifiedAt     int32  `db:"modified"`
	PublicName     string `db:"yk_publicname"`
	SessionCounter int32  `db:"yk_counter"`
	UseCounter     int32  `db:"yk_use"`
	Low            int32  `db:"yk_low"`
	High           int32  `db:"yk_high"`
	Nonce          string `db:"nonce"`
	Notes          string `db:"notes"`
}

type Params struct {
	YubiKey
	Signature string
	ClientId  int32
	Timestamp int32
	Otp       string
	SyncLevel string
	Timeout   int32
}
