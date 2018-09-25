# To run UTs
1. Create a Key Protect Service in the US South region.
2. Create a Root Key
3. Get the Service API Key and the Instance ID using the steps describe under pkg/ibm/README.md

```
$ IBM_SERVICE_API_KEY=<api_key> IBM_INSTANCE_ID=<instance_id> IBM_CUSTOMER_ROOT_KEY=<crk>
```