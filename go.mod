module github.com/libopenstorage/secrets

go 1.13

require (
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.29
	github.com/Azure/go-autorest/autorest/adal v0.9.23
	github.com/Azure/go-autorest/autorest/to v0.4.0
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
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	google.golang.org/api v0.139.0
	k8s.io/client-go v12.0.0+incompatible
)

require (
	github.com/IBM-Cloud/hpcs-grep11-go v1.2.2
	github.com/hashicorp/vault/sdk v0.11.1
	github.com/imdario/mergo v0.3.13 // indirect
	golang.org/x/oauth2 v0.13.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v14.2.0+incompatible
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
	github.com/kubernetes-incubator/external-storage => github.com/libopenstorage/external-storage v5.1.0-openstorage+incompatible
	github.com/kubernetes-incubator/external-storage v0.0.0-00010101000000-000000000000 => github.com/libopenstorage/external-storage v5.1.0-openstorage+incompatible
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20190424153033-d3245f150225

	k8s.io/api => k8s.io/api v0.29.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.29.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.29.3
	k8s.io/apiserver => k8s.io/apiserver v0.29.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.29.3
	k8s.io/client-go => k8s.io/client-go v0.29.3
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.29.3
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.29.3
	k8s.io/code-generator => k8s.io/code-generator v0.29.3
	k8s.io/component-base => k8s.io/component-base v0.29.3
	k8s.io/component-helpers => k8s.io/component-helpers v0.29.3
	k8s.io/controller-manager => k8s.io/controller-manager v0.29.3
	k8s.io/cri-api => k8s.io/cri-api v0.29.3
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.29.3

	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.29.3
	k8s.io/endpointslice => k8s.io/endpointslice v0.29.3
	k8s.io/kms => k8s.io/kms v0.29.3
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.29.3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.29.3
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.29.3
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.29.3
	k8s.io/kubectl => k8s.io/kubectl v0.29.3
	k8s.io/kubelet => k8s.io/kubelet v0.29.3
	k8s.io/kubernetes => k8s.io/kubernetes v1.29.3
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.29.3
	k8s.io/metrics => k8s.io/metrics v0.29.3
	k8s.io/mount-utils => k8s.io/mount-utils v0.29.3
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.29.3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.29.3
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.29.3
	k8s.io/sample-controller => k8s.io/sample-controller v0.29.3
)
