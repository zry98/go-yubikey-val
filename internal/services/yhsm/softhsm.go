package yhsm

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
)

type Yhsm struct {
	keys map[int32][]byte
}

func (softYhsm *Yhsm) fromJson(jsonStr string, debug bool) error {
	data := make(map[int32]interface{})
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return err
	}

	softYhsm.keys = make(map[int32][]byte, len(data))
	for kh, aesKeyHex := range data {
		key, err := hex.DecodeString(aesKeyHex.(string))
		if err != nil {
			return err
		}
		softYhsm.keys[kh] = key
	}

	return nil
}

func (softYhsm *Yhsm) fromFile(filename string, debug bool) error {
	jsonBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = softYhsm.fromJson(string(jsonBytes), debug)
	if err != nil {
		return err
	}

	return nil
}
