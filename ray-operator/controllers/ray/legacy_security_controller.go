package ray

import (
	"context"
	"reflect"

	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	"github.com/ray-project/kuberay/ray-operator/controllers/ray/utils"
	"github.com/ray-project/kuberay/ray-operator/pkg/features"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// LegacySecurityController migrates the downstream OpenShift security annotation
// to upstream RayCluster fields. Resource ownership remains with the native
// mTLS and NetworkPolicy controllers.
type LegacySecurityController struct {
	client.Client
	isOpenShift bool
}

func NewLegacySecurityController(mgr manager.Manager, isOpenShift bool) *LegacySecurityController {
	return &LegacySecurityController{Client: mgr.GetClient(), isOpenShift: isOpenShift}
}

// +kubebuilder:rbac:groups=ray.io,resources=rayclusters,verbs=get;list;watch;patch
func (r *LegacySecurityController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	cluster := &rayv1.RayCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	if !r.isOpenShift || !features.Enabled(features.RayClusterMTLS) || !features.Enabled(features.RayClusterNetworkPolicy) ||
		cluster.Annotations[utils.EnableSecureTrustedNetworkAnnotationKey] != "true" {
		return reconcile.Result{}, nil
	}

	before := cluster.DeepCopy()
	utils.EnsureOpenShiftRayClusterSecurity(cluster)
	if reflect.DeepEqual(before.Spec, cluster.Spec) {
		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, r.Patch(ctx, cluster, client.MergeFrom(before))
}

func (r *LegacySecurityController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("raycluster-legacy-security").
		For(&rayv1.RayCluster{}).
		Complete(r)
}
