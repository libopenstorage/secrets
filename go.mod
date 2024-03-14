module github.com/libopenstorage/secrets

go 1.13

require (
	github.com/IBM/keyprotect-go-client v0.5.1
	github.com/aws/aws-sdk-go v1.44.164
	github.com/golang/mock v1.6.0
	github.com/hashicorp/vault/api v1.10.0
	github.com/hashicorp/vault/api/auth/approle v0.5.0
	github.com/hashicorp/vault/api/auth/kubernetes v0.5.0
	github.com/pborman/uuid v1.2.0
	github.com/portworx/dcos-secrets v0.0.0-20180616013705-8e8ec3f66611
	github.com/portworx/kvdb v0.0.0-20200929023115-b312c7519467
	github.com/portworx/sched-ops v1.20.4-rc1
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.4
	google.golang.org/api v0.83.0
	k8s.io/client-go v12.0.0+incompatible
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.5.1
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets v0.12.0
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-test/deep v1.0.8 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/ginkgo/v2 v2.6.0 // indirect
	github.com/onsi/gomega v1.24.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401
	golang.org/x/time v0.3.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	k8s.io/api v0.26.0 // indirect
	k8s.io/apimachinery v0.26.0 // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v14.2.0+incompatible
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
	github.com/kubernetes-incubator/external-storage => github.com/libopenstorage/external-storage v5.1.0-openstorage+incompatible
	github.com/kubernetes-incubator/external-storage v0.0.0-00010101000000-000000000000 => github.com/libopenstorage/external-storage v5.1.0-openstorage+incompatible
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20190424153033-d3245f150225

	k8s.io/api => k8s.io/api v0.25.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.25.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.25.1
	k8s.io/apiserver => k8s.io/apiserver v0.25.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.25.1
	k8s.io/client-go => k8s.io/client-go v0.25.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.25.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.25.1
	k8s.io/code-generator => k8s.io/code-generator v0.25.1
	k8s.io/component-base => k8s.io/component-base v0.25.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.25.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.25.1
	k8s.io/cri-api => k8s.io/cri-api v0.25.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.25.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.25.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.25.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.25.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.25.1
	k8s.io/kubectl => k8s.io/kubectl v0.25.1
	k8s.io/kubelet => k8s.io/kubelet v0.25.1
	k8s.io/kubernetes => k8s.io/kubernetes v1.25.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.25.1
	k8s.io/metrics => k8s.io/metrics v0.25.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.25.1
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.25.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.25.1
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.25.1
	k8s.io/sample-controller => k8s.io/sample-controller v0.25.1
)
