package main

import (
	"context"
	"fmt"
	"strings"

	"github.ibm.com/kms/key-protect-client"
)

func getConfigAuthToken() kp.ClientConfig {
	return kp.ClientConfig{
		BaseURL:       kp.DefaultBaseURL,
		Authorization: "",
		InstanceID:    "",
		Verbose:       kp.VerboseFailOnly,
	}
}

func getConfigAPIKey() kp.ClientConfig {
	return kp.ClientConfig{
		BaseURL:    kp.DefaultBaseURL,
		APIKey:     "",
		TokenURL:   kp.DefaultTokenURL,
		InstanceID: "",
		Verbose:    kp.VerboseFailOnly,
	}
}

func standardKeyOperations(api *kp.API) {

	fmt.Println("\nCreating standard key")
	rootkey, err := api.CreateStandardKey(context.Background(), "mynewstandardkey", nil)
	if err != nil {
		fmt.Println("Error while creating standard key: ", err)
		return
	}
	fmt.Println("New key created: ", *rootkey)

	fmt.Println("\nGetting standard key")
	keyid := rootkey.ID
	key, err := api.GetKey(context.Background(), keyid)
	if err != nil {
		fmt.Println("Get Key failed with error: ", err)
		return
	}
	fmt.Printf("Key: %v\n", *key)

	fmt.Println("\nDeleting standard key")
	delKey, err := api.DeleteKey(context.Background(), keyid, kp.ReturnRepresentation)
	if err != nil {
		fmt.Println("Error while deleting: ", err)
		return
	}
	fmt.Println("Deleted key: ", delKey)
}

func rootKeyOperations(api *kp.API) {

	fmt.Println("\nCreating root key")
	rootkey, err := api.CreateRootKey(context.Background(), "mynewrootkey", nil)
	if err != nil {
		fmt.Println("Error while creating root key: ", err)
		return
	}
	fmt.Println("New key created: ", *rootkey)

	fmt.Println("\nGetting root key")
	keyid := rootkey.ID
	key, err := api.GetKey(context.Background(), keyid)
	if err != nil {
		fmt.Println("Get Key failed with error: ", err)
		return
	}
	fmt.Printf("Key: %v\n", *key)

	fmt.Println("\nWrapping root key")
	aad := []string{"string1", "string2", "string3"}
	plaintext := []byte("This is my fav root key")
	ciphertext, err := api.Wrap(context.Background(), keyid, plaintext, &aad)
	if err != nil {
		fmt.Println("Error wrapping the key: ", err)
		return
	}
	fmt.Println("Wrapped key successfully")

	fmt.Println("\nUnwrapping root key")
	pt, err := api.Unwrap(context.Background(), keyid, ciphertext, &aad)
	if err != nil {
		fmt.Println("Error unwrapping key: ", err)
		return
	}
	if strings.Compare(string(plaintext), string(pt)) == 0 {
		fmt.Println("key wrapped and unwrapped successully")
	}

	fmt.Println("Creating a DEK")

	DEK2, wrappedDek, err := api.WrapCreateDEK(context.Background(), keyid, nil)
	if err != nil {
		fmt.Println("Error while creating a DEK: ", err)
		return
	}

	fmt.Println("Created DEK and wrapped the key")

	pt2, err := api.Unwrap(context.Background(), keyid, wrappedDek, nil)
	if err != nil {
		fmt.Println("Error while unwrapping DEK: ", err)
		return
	}
	if strings.Compare(string(DEK2), string(pt2)) == 0 {
		fmt.Println("Unwrapped key successfully")
	}

	DEK1, wrappedDek1, err := api.WrapCreateDEK(context.Background(), keyid, &aad)
	if err != nil {
		fmt.Println("Error while creating a DEK with aad: ", err)
		return
	}
	fmt.Println("Created DEK and wrapped the key with aad")

	ptxt, err := api.Unwrap(context.Background(), keyid, wrappedDek1, &aad)
	if err != nil {
		fmt.Println("Error while unwrapping DEK: ", err)
		return
	}
	if strings.Compare(string(DEK1), string(ptxt)) == 0 {
		fmt.Println("Unwrapped key successfully with aad")
	}

	fmt.Println("\nDeleting root key")
	delKey, err := api.DeleteKey(context.Background(), keyid, kp.ReturnRepresentation)
	if err != nil {
		fmt.Println("Error while deleting: ", err)
		return
	}
	fmt.Println("Deleted key: ", delKey)
}
func main() {
	options := getConfigAPIKey()
	api, err := kp.New(options, kp.DefaultTransport())
	if err != nil {
		fmt.Println("Error creating kp client")
		return
	}

	standardKeyOperations(api)
	rootKeyOperations(api)

	fmt.Println("\nGetting all keys")
	keys, err := api.GetKeys(context.Background(), 100, 0)
	if err != nil {
		fmt.Println("Get Keys failed with error: ", err)
		return
	}
	fmt.Printf("Keys: %v\n", keys)

}
