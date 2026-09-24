// TODO: This file is a transitional shim for OpenShift-specific Route creation. Once Gateway API
// support is mature and the Route-based backward compatibility window closes, this file and all
// associated OpenShift-specific code paths should be removed. See the roadmap summary at:
// https://github.com/ray-project/kuberay/pull/4365#issuecomment-4143407845

package utils

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// openShiftAPIGroups lists the API groups used to detect an OpenShift cluster.
// We check for specific well-known groups rather than using a broad suffix match
// (e.g. strings.HasSuffix(".openshift.io")) to avoid false positives from custom
// CRDs that happen to use the openshift.io domain but don't indicate a real
// OpenShift installation. Any one of these groups being present is sufficient.
var openShiftAPIGroups = []string{
	"route.openshift.io",
	"security.openshift.io",
	"config.openshift.io",
}

// IsOpenShiftCluster detects if the cluster is OpenShift by checking for OpenShift-specific API groups.
// This function is called once at operator startup and the result is stored in reconciler options.
// Returns an error if cluster type cannot be determined, since downstream behavior (e.g. Route
// vs Ingress creation) depends on this check being accurate.
func IsOpenShiftCluster(config *rest.Config) (bool, error) {
	if config == nil {
		return false, fmt.Errorf("REST config is nil")
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create discovery client: %w", err)
	}

	apiGroups, err := discoveryClient.ServerGroups()
	if err != nil {
		return false, fmt.Errorf("failed to retrieve server API groups: %w", err)
	}

	for _, group := range apiGroups.Groups {
		if slices.Contains(openShiftAPIGroups, group.Name) {
			return true, nil
		}
	}

	return false, nil
}

// ShouldUseIngressOnOpenShift determines if Ingress should be used instead of Route on OpenShift.
func ShouldUseIngressOnOpenShift() bool {
	return strings.ToLower(os.Getenv(USE_INGRESS_ON_OPENSHIFT)) == "true"
}

// EnsureOpenShiftRayClusterSecurity applies the OpenShift security contract to
// a RayCluster. It is deliberately idempotent so it can migrate existing
// RayClusters as they are reconciled after an operator upgrade.
func EnsureOpenShiftRayClusterSecurity(cluster *rayv1.RayCluster) bool {
	original := cluster.DeepCopy()

	if cluster.Annotations == nil {
		cluster.Annotations = make(map[string]string)
	}
	cluster.Annotations[EnableSecureTrustedNetworkAnnotationKey] = "true"

	enabled := true
	cluster.Spec.TLSOptions = &rayv1.TLSOptions{Enabled: &enabled}
	ensureOpenShiftNetworkPolicy(&cluster.Spec)

	falseValue := false
	cluster.Spec.HeadGroupSpec.EnableIngress = &falseValue

	return !reflect.DeepEqual(original.Annotations, cluster.Annotations) ||
		!reflect.DeepEqual(original.Spec, cluster.Spec)
}

func ensureOpenShiftNetworkPolicy(spec *rayv1.RayClusterSpec) {
	mode := rayv1.NetworkPolicyDenyAllIngress
	if spec.NetworkPolicy == nil {
		spec.NetworkPolicy = &rayv1.NetworkPolicyConfig{}
	}
	spec.NetworkPolicy.Mode = &mode
	if spec.NetworkPolicy.Head == nil {
		spec.NetworkPolicy.Head = &rayv1.NetworkPolicyRules{}
	}
	if spec.NetworkPolicy.Worker == nil {
		spec.NetworkPolicy.Worker = &rayv1.NetworkPolicyRules{}
	}

	tcp := corev1.ProtocolTCP
	port := func(value int32) networkingv1.NetworkPolicyPort {
		p := intstr.FromInt32(value)
		return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &p}
	}
	appendIngress := func(rules []networkingv1.NetworkPolicyIngressRule, rule networkingv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyIngressRule {
		for _, existing := range rules {
			if reflect.DeepEqual(existing, rule) {
				return rules
			}
		}
		return append(rules, rule)
	}

	// Same-namespace dashboard/client access.
	spec.NetworkPolicy.Head.IngressRules = appendIngress(spec.NetworkPolicy.Head.IngressRules, networkingv1.NetworkPolicyIngressRule{
		From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}},
		Ports: []networkingv1.NetworkPolicyPort{port(8265), port(10001)},
	})

	// The authenticated proxy is deliberately reachable from any namespace; the
	// proxy itself performs the authentication check on port 8443.
	spec.NetworkPolicy.Head.IngressRules = appendIngress(spec.NetworkPolicy.Head.IngressRules, networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{port(8443)},
	})

	// Allow the operator and Gateway API ingress to reach the dashboard/client.
	namespaces := []string{}
	if namespace := os.Getenv("APPLICATION_NAMESPACE"); namespace != "" {
		namespaces = append(namespaces, namespace)
	}
	if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
		namespaces = append(namespaces, namespace)
	}
	if len(namespaces) == 0 {
		namespaces = []string{"redhat-ods-applications", "opendatahub"}
	}
	operatorPeer := networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{KubernetesApplicationNameLabelKey: ApplicationName}},
		NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: corev1.LabelMetadataName, Operator: metav1.LabelSelectorOpIn, Values: namespaces,
		}}},
	}
	spec.NetworkPolicy.Head.IngressRules = appendIngress(spec.NetworkPolicy.Head.IngressRules, networkingv1.NetworkPolicyIngressRule{
		From: []networkingv1.NetworkPolicyPeer{operatorPeer}, Ports: []networkingv1.NetworkPolicyPort{port(8265), port(10001)},
	})

	gatewayNamespace := os.Getenv("GATEWAY_NAMESPACE")
	if gatewayNamespace == "" {
		gatewayNamespace = "openshift-ingress"
	}
	spec.NetworkPolicy.Head.IngressRules = appendIngress(spec.NetworkPolicy.Head.IngressRules, networkingv1.NetworkPolicyIngressRule{
		From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: corev1.LabelMetadataName, Operator: metav1.LabelSelectorOpIn, Values: []string{gatewayNamespace},
		}}}}},
		Ports: []networkingv1.NetworkPolicyPort{port(8265)},
	})
}
