package libolm

import (
	"github.com/justinbarrick/go-matrix/pkg/client/end_to_end_encryption"
	"github.com/justinbarrick/go-matrix/pkg/models"

	"encoding/json"
	"fmt"
	"github.com/tent/canonical-json-go"
	"os"
)

type UserSession struct {
	Session    Session
	UserId     string
	DeviceId   string
	DeviceKey  string
	Ed25519Key string
}

type BotState struct {
	MatrixAccount string
}

type IdentityKeys struct {
	Curve25519 string `json:"curve25519"`
	Ed25519    string `json:"ed25519"`
}

type OneTimeKeys struct {
	Curve25519 map[string]string `json:"curve25519"`
}

type Matrix struct {
	account Account
}

func NewMatrix() (*Matrix, error) {
	olm := &Matrix{}

	if _, err := os.Stat("state.json"); os.IsNotExist(err) {
		olm.account = CreateNewAccount()
		olm.account.GenerateOneTimeKeys(100)
		err = olm.Serialize()
		if err != nil {
			return olm, nil
		}
	} else {
		err = olm.Deserialize()
		if err != nil {
			return olm, nil
		}
	}

	return olm, nil
}

func (o *Matrix) Deserialize() error {
	f, err := os.Open("state.json")
	if err != nil {
		return err
	}

	defer f.Close()

	botState := BotState{}

	err = json.NewDecoder(f).Decode(&botState)
	if err != nil {
		return err
	}

	o.account = AccountFromPickle("lol", botState.MatrixAccount)
	return nil
}

func (o *Matrix) Serialize() error {
	f, err := os.Create("state.json")
	if err != nil {
		return err
	}

	defer f.Close()

	err = json.NewEncoder(f).Encode(BotState{
		MatrixAccount: o.account.Pickle("lol"),
	})
	if err != nil {
		return err
	}

	return nil
}

func (o *Matrix) GetIdentityKeys() IdentityKeys {
	identityKeys := IdentityKeys{}
	json.Unmarshal([]byte(o.account.GetIdentityKeys()), &identityKeys)
	return identityKeys
}

func (o *Matrix) GetOneTimeKeys() OneTimeKeys {
	oneTimeKeysDecoded := OneTimeKeys{}
	json.Unmarshal([]byte(o.account.GetOneTimeKeys()), &oneTimeKeysDecoded)
	return oneTimeKeysDecoded
}

func (o *Matrix) SignObj(obj interface{}) (string, error) {
	output, err := cjson.Marshal(obj)
	if err != nil {
		return "", err
	}

	signature := o.account.Sign(string(output))
	return signature, nil
}

func (o *Matrix) UploadKeysParams(deviceId, userId string) (*end_to_end_encryption.UploadKeysParams, error) {
	oneTimeKeys := map[string]string{}
	for id, curve25519Key := range o.GetOneTimeKeys().Curve25519 {
		oneTimeKeys[fmt.Sprintf("curve25519:%s", id)] = curve25519Key
	}

	identityKeys := o.GetIdentityKeys()

	deviceKeys := &models.UploadKeysParamsBodyDeviceKeys{
		models.UploadKeysParamsBodyDeviceKeysAllOf0{
			Algorithms: []string{
				"m.megolm.v1.aes-sha",
				"m.olm.curve25519-aes-sha256",
			},
			DeviceID: &deviceId,
			Keys: map[string]string{
				fmt.Sprintf("curve25519:%s", deviceId): identityKeys.Curve25519,
				fmt.Sprintf("ed25519:%s", deviceId):    identityKeys.Ed25519,
			},
			UserID: &userId,
		},
	}

	signature, err := o.SignObj(deviceKeys)
	if err != nil {
		return nil, err
	}

	deviceKeys.Signatures = map[string]map[string]string{
		userId: map[string]string{
			fmt.Sprintf("ed25519:%s", deviceId): signature,
		},
	}

	uploadKeys := end_to_end_encryption.NewUploadKeysParams()
	uploadKeys.SetKeys(&models.UploadKeysParamsBody{
		DeviceKeys:  deviceKeys,
		OneTimeKeys: oneTimeKeys,
	})

	return uploadKeys, nil
}

func (o *Matrix) MarkPublished() error {
	o.account.MarkKeysAsPublished()
	return o.Serialize()
}

func (o *Matrix) GetAccount() Account {
	return o.account
}
