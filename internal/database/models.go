package database

type Client struct {
	Id        int32  `db:"id"`
	Active    bool   `db:"active"`
	CreatedAt int32  `db:"created_at"`
	Secret    string `db:"secret"`
	Email     string `db:"email"`
	Notes     string `db:"notes"`
	Otp       string `db:"otp"`
}

type YubiKey struct {
	Active         bool   `db:"active"`
	CreatedAt      int32  `db:"created_at"`
	ModifiedAt     int32  `db:"modified_at"`
	PublicName     string `db:"public_name"`
	SessionCounter int32  `db:"session_counter"`
	UseCounter     int32  `db:"use_counter"`
	TimestampLow   int32  `db:"timestamp_low"`
	TimestampHigh  int32  `db:"timestamp_high"`
	Nonce          string `db:"nonce"`
	Notes          string `db:"notes"`
	SecretKey      string `db:"secret_key"`
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
