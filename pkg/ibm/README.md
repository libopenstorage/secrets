The pkg ibm is provides a golang REST client to talk with IBM's Key Protect Service.
It has been provided to us by the IKS team.
Thanks to Karna Bojjireddy (karub@us.ibm.com) and Sandip Amin (samin@us.ibm.com) for providing this library.

# Key Protect Service Client

## Usage

This client requires that you have an existing IBM Cloud Key Protect Service, for more information see:
https://console.bluemix.net/catalog/services/key-protect/.  Note: The client currently only supports
key protect service instances and not the older cloud foundry service instances.  Support for cloud foundry instances
may be added in the future.

The key protect service requires a valid IAM access token or a service id API Key.  When using your own token, it's the responsibilty
of the caller to ensure the access token is valid and is not expired.  You can specify the access token in either the client configuration
structure or on the context (see below).  If you specify an APIKey, the client calls IAM to get an access token for that API key and reuses
that token on subsequent calls. If the API key token is expired, the client will call IAM to get a new access token.

To use the client you will need the following:

* Access Token
  * Either an IBM Cloud access token which you can get by doing the following in the bx cli:
    * Login
    * Once logged, run `bx iam oauth-tokens`.  The `IAM token` is what you need, including the words `Bearer`.
  * Or a service ID API key.  For more information on creating an API key see the key protect documentation:
https://console.bluemix.net/docs/services/keymgmt/keyprotect_authentication.html#retrieve_token.  Follow steps 1-3
to get an API key.  You do NOT have the get an access token from the API key as the client will take care of that for you.
* The UUID of the key protect service:
  * Run the following commands:
    * `bx resource service-instances`
    * Find your key protect service ID by running the following:
      * `bx resource service-instance <name of your key protect service>`
      * The ID will look something like this:
        ```
        ID:                    crn:v1:bluemix:public:kms:us-south:a/fb474855a3e76c1ce3aaebf57e0f1a9f:0647c737-blah1-blah2-8a68-2c187e11b29b::
        ```
        This ID is the full CRN.  You need to specify just id portion which is everything between the last `:` and `::`, in this example
        the id to use is: `0647c737-906d-blah1-blah2-2c187e11b29b`

Once you have those pieces of information, you can create a client as follows:
Note: BaseURL specifies the URL where your key protect instance resides.  It is region specific.  See Config.go DefaultBaseURL for a sample.
Note: There are 3 ways to provide the authorization token.
1. In the ClientConfig structure specify the `APIKey` and the `TokenURL` attributes.  A default token url can be found in config.go DefaultTokenURL.
The client will take care of obtaining an access token.
2. In the ClientConfig structure specify the `Authorization` attribute.  All key protect API calls using that client will use that authorization token.
3. In the context on each call. You can create an authorization context by using the `kp.NewContextWithAuth()` function.  If you specify more
than 1 authentication method, the precedence is:
   1. Context
   1. Authorization in the ClientConfig structure
   1. API key in the ClientConfig structure

```
// Create the client config using your API key

c := kp.ClientConfig{
		BaseURL:       kp.DefaultBaseURL,
	  APIKey:        "<api-key>",
		TokenURL:      DefaultTokenURL,
		InstanceID:    "<instance-id>",
		Verbose:       kp.VerboseAll,
	}

// Create the API.  You can specify your own http transport object or use a default one provided by the client.

api := kp.NewAPI(c, kp.DefaultTransport())

// Now you can call the apis

keys, err := api.GetKeys(context.Background(), 0, 0)
....
```

To specify authorization token on the context:

```
// Create the client config with authorization

c := kp.ClientConfig{
		BaseURL:       kp.DefaultBaseURL,
		InstanceID:    "<instance-id>",
		Verbose:       kp.VerboseAll,
	}

// Create the API.  You can specify your own http transport object or use a default one provided by the client.

api := kp.NewAPI(c, kp.DefaultTransport())

ctx := kp.NewContextWithAuth(context.Background(), "Bearer <auth info>")

// Now you can call the apis

keys, err := api.GetKeys(ctx, 0, 0)
....
```

## Generating a root key (CRK)

```
//Create a root key named MyRootKey with no expiration
key, err := api.CreateRootKey(ctx, "MyRootKey", nil)
if err != nil {
    fmt.Println(err)
}
fmt.Println(key.ID, key.Name)

crkID := key.ID
```

## Wrapping and Unwrapping a DEK using a specific Root Key.

```
myDEK := []byte{"thisisadataencryptionkey"}
// Do some encryption with myDEK
// Wrap the DEK so we can safely store it
wrappedDEK, err := api.Wrap(ctx, crkID, myDEK, nil)


//Unwrap the DEK
dek, err := api.UnWrap(ctx, crkID, wrappedDEK, nil)
//Do some encryption/decryption using the DEK
//Discard the DEK
dek = nil

```

Note you can also pass additional authentication data (AAD) to wrap and unwrap calls
to provide another level of protection for your DEK.  The AAD is a string array with
each element up to 255 chars.  For example:

```
myAAD := []string{"First aad string", "second aad string", "third aad string"}
myDEK := []byte{"thisisadataencryptionkey"}
// Do some encryption with myDEK
// Wrap the DEK so we can safely store it
wrappedDEK, err := api.Wrap(ctx, crkID, myDEK, &myAAD)


//Unwrap the DEK
dek, err := api.UnWrap(ctx, crkID, wrappedDEK, &myAAD)
//Do some encryption/decryption using the DEK
//Discard the DEK
dek = nil

```

Have key protect create a DEK for you:

```

dek, wrappedDek, err := api.WrapCreateDEK(ctx, crkID, nil)
//Do some encrypt/decrypt with the dek
//Discard the DEK
dek = nil

//Save the wrapped DEK for later.  Use Unwrap to use it.

```

Can also specify AAD:

```
myAAD := []string{"First aad string", "second aad string", "third aad string"}
dek, wrappedDek, err := api.WrapCreateDEK(ctx, crkID, &myAAD)
//Do some encrypt/decrypt with the dek
//Discard the DEK
dek = nil

//Save the wrapped DEK for later.  Call Unwrap to use it, make
//sure to specify the same AAD.

```

## Running the test cases
