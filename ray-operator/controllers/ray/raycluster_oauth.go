/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ray

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"reflect"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	rbac "k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/utils/pointer"

	routev1 "github.com/openshift/api/route/v1"
	rayv1 "github.com/ray-project/kuberay/ray-operator/apis/ray/v1"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	OAuthServicePort     = 443
	OAuthServicePortName = "oauth-proxy"
	OAuthProxyImage      = "registry.redhat.io/openshift4/ose-oauth-proxy:latest"
)

type OAuthConfig struct {
	ProxyImage string
}

// NewClusterServiceAccount defines the desired service account object
func NewClusterServiceAccount(cluster *rayv1.RayCluster) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				"cluster-name": cluster.Name,
			},
			Annotations: map[string]string{
				"serviceaccounts.openshift.io/oauth-redirectreference.first": "" +
					`{"kind":"OAuthRedirectReference","apiVersion":"v1",` +
					`"reference":{"kind":"Route","name":"` + cluster.Name + `"}}`,
			},
		},
	}
}

// CompareRayClusterServiceAccounts checks if two service accounts are equal, if
// not return false
func CompareRayClusterServiceAccounts(sa1 corev1.ServiceAccount, sa2 corev1.ServiceAccount) bool {
	// Two service accounts will be equal if the labels and annotations are
	// identical
	return reflect.DeepEqual(sa1.ObjectMeta.Labels, sa2.ObjectMeta.Labels) &&
		reflect.DeepEqual(sa1.ObjectMeta.Annotations, sa2.ObjectMeta.Annotations)
}

// ReconcileOAuthServiceAccount will manage the service account reconciliation
// required by the notebook OAuth proxy
func (r *RayClusterReconciler) ReconcileOAuthServiceAccount(cluster *rayv1.RayCluster, ctx context.Context) error {
	// Initialize logger format
	log := ctrl.LoggerFrom(ctx)

	// Generate the desired service account
	desiredServiceAccount := NewClusterServiceAccount(cluster)

	// Create the service account if it does not already exist
	foundServiceAccount := &corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredServiceAccount.Name,
		Namespace: cluster.Namespace,
	}, foundServiceAccount)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Info("Creating Service Account")
			// Add .metatada.ownerReferences to the service account to be deleted by
			// the Kubernetes garbage collector if the notebook is deleted
			err = ctrl.SetControllerReference(cluster, desiredServiceAccount, r.Scheme)
			if err != nil {
				log.Error(err, "Unable to add OwnerReference to the Service Account")
				return err
			}
			// Create the service account in the Openshift cluster
			err = r.Create(ctx, desiredServiceAccount)
			if err != nil && !apierrs.IsAlreadyExists(err) {
				log.Error(err, "Unable to create the Service Account")
				return err
			}
		} else {
			log.Error(err, "Unable to fetch the Service Account")
			return err
		}
	}

	return nil
}

func NewOAuthClusterRoleBinding(cluster *rayv1.RayCluster) *rbac.ClusterRoleBinding {
	return &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: cluster.Name + "-auth",
			Labels: map[string]string{
				"cluster-name": cluster.Name,
			},
		},
		Subjects: []rbac.Subject{{
			Kind:      "ServiceAccount",
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
		}},
		RoleRef: rbac.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "system:auth-delegator",
		},
	}
}

func (r *RayClusterReconciler) ReconcileOAuthClusterRoleBinding(cluster *rayv1.RayCluster, ctx context.Context) error {
	// Initialize logger format
	log := ctrl.LoggerFrom(ctx)

	// Generate the desired service account
	desiredCRB := NewOAuthClusterRoleBinding(cluster)

	// Create the service account if it does not already exist
	foundCRB := &corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredCRB.Name,
		Namespace: cluster.Namespace,
	}, foundCRB)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Info("Creating ClusterRoleBinding")
			// Add .metatada.ownerReferences to the service account to be deleted by
			// the Kubernetes garbage collector if the notebook is deleted
			err = ctrl.SetControllerReference(cluster, desiredCRB, r.Scheme)
			if err != nil {
				log.Error(err, "Unable to add OwnerReference to the Service Account")
				return err
			}
			// Create the service account in the Openshift cluster
			err = r.Create(ctx, desiredCRB)
			if err != nil && !apierrs.IsAlreadyExists(err) {
				log.Error(err, "Unable to create the ClusterRoleBinding")
				return err
			}
		} else {
			log.Error(err, "Unable to fetch the ClusterRoleBinding")
			return err
		}
	}

	return nil
}

// NewClusterOAuthService defines the desired OAuth service object
func NewClusterOAuthService(cluster *rayv1.RayCluster) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-tls",
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				"cluster-name": cluster.Name,
			},
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": cluster.Name + "-tls",
			},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Name:       OAuthServicePortName,
				Port:       OAuthServicePort,
				TargetPort: intstr.FromString(OAuthServicePortName),
				Protocol:   corev1.ProtocolTCP,
			}},
			Selector: map[string]string{
				"ray.io/cluster":   cluster.Name,
				"ray.io/node-type": "head",
			},
		},
	}
}

// CompareNotebookServices checks if two services are equal, if not return false
func CompareNotebookServices(s1 corev1.Service, s2 corev1.Service) bool {
	// Two services will be equal if the labels and annotations are identical
	return reflect.DeepEqual(s1.ObjectMeta.Labels, s2.ObjectMeta.Labels) &&
		reflect.DeepEqual(s1.ObjectMeta.Annotations, s2.ObjectMeta.Annotations)
}

// ReconcileOAuthService will manage the OAuth service reconciliation required
// by the notebook OAuth proxy
func (r *RayClusterReconciler) ReconcileOAuthService(cluster *rayv1.RayCluster, ctx context.Context) error {
	// Initialize logger format
	log := ctrl.LoggerFrom(ctx)

	// Generate the desired OAuth service
	desiredService := NewClusterOAuthService(cluster)

	// Create the OAuth service if it does not already exist
	foundService := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredService.GetName(),
		Namespace: cluster.GetNamespace(),
	}, foundService)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Info("Creating OAuth Service")
			// Add .metatada.ownerReferences to the OAuth service to be deleted by
			// the Kubernetes garbage collector if the cluster is deleted
			err = ctrl.SetControllerReference(cluster, desiredService, r.Scheme)
			if err != nil {
				log.Error(err, "Unable to add OwnerReference to the OAuth Service")
				return err
			}
			// Create the OAuth service in the Openshift cluster
			err = r.Create(ctx, desiredService)
			if err != nil && !apierrs.IsAlreadyExists(err) {
				log.Error(err, "Unable to create the OAuth Service")
				return err
			}
		} else {
			log.Error(err, "Unable to fetch the OAuth Service")
			return err
		}
	}

	return nil
}

// NewClusterOAuthSecret defines the desired OAuth secret object
func NewClusterOAuthSecret(cluster *rayv1.RayCluster) *corev1.Secret {
	// Generate the cookie secret for the OAuth proxy
	cookieSeed := make([]byte, 16)
	rand.Read(cookieSeed)
	cookieSecret := base64.StdEncoding.EncodeToString(
		[]byte(base64.StdEncoding.EncodeToString(cookieSeed)))

	// Create a Kubernetes secret to store the cookie secret
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-oauth-config",
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				"cluster-name": cluster.Name,
			},
		},
		StringData: map[string]string{
			"cookie_secret": cookieSecret,
		},
	}
}

// ReconcileOAuthSecret will manage the OAuth secret reconciliation required by
// the cluster OAuth proxy
func (r *RayClusterReconciler) ReconcileOAuthSecret(cluster *rayv1.RayCluster, ctx context.Context) error {
	// Initialize logger format
	log := ctrl.LoggerFrom(ctx)

	// Generate the desired OAuth secret
	desiredSecret := NewClusterOAuthSecret(cluster)

	// Create the OAuth secret if it does not already exist
	foundSecret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredSecret.Name,
		Namespace: cluster.Namespace,
	}, foundSecret)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Info("Creating OAuth Secret")
			// Add .metatada.ownerReferences to the OAuth secret to be deleted by
			// the Kubernetes garbage collector if the cluster is deleted
			err = ctrl.SetControllerReference(cluster, desiredSecret, r.Scheme)
			if err != nil {
				log.Error(err, "Unable to add OwnerReference to the OAuth Secret")
				return err
			}
			// Create the OAuth secret in the Openshift cluster
			err = r.Create(ctx, desiredSecret)
			if err != nil && !apierrs.IsAlreadyExists(err) {
				log.Error(err, "Unable to create the OAuth Secret")
				return err
			}
		} else {
			log.Error(err, "Unable to fetch the OAuth Secret")
			return err
		}
	}

	return nil
}

// CompareNotebookRoutes checks if two routes are equal, if not return false
func CompareNotebookRoutes(r1 routev1.Route, r2 routev1.Route) bool {
	// Omit the host field since it is reconciled by the ingress controller
	r1.Spec.Host, r2.Spec.Host = "", ""

	// Two routes will be equal if the labels and spec are identical
	return reflect.DeepEqual(r1.ObjectMeta.Labels, r2.ObjectMeta.Labels) &&
		reflect.DeepEqual(r1.Spec, r2.Spec)
}

func (r *RayClusterReconciler) reconcileRoute(cluster *rayv1.RayCluster,
	ctx context.Context, newRoute func(*rayv1.RayCluster) *routev1.Route) error {
	// Initialize logger format
	log := r.Log.WithValues("notebook", cluster.Name, "namespace", cluster.Namespace)

	// Generate the desired route
	desiredRoute := newRoute(cluster)

	// Create the route if it does not already exist
	foundRoute := &routev1.Route{}
	justCreated := false
	err := r.Get(ctx, types.NamespacedName{
		Name:      desiredRoute.Name,
		Namespace: cluster.Namespace,
	}, foundRoute)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Info("Creating Route")
			// Add .metatada.ownerReferences to the route to be deleted by the
			// Kubernetes garbage collector if the notebook is deleted
			err = ctrl.SetControllerReference(cluster, desiredRoute, r.Scheme)
			if err != nil {
				log.Error(err, "Unable to add OwnerReference to the Route")
				return err
			}
			// Create the route in the Openshift cluster
			err = r.Create(ctx, desiredRoute)
			if err != nil && !apierrs.IsAlreadyExists(err) {
				log.Error(err, "Unable to create the Route")
				return err
			}
			justCreated = true
		} else {
			log.Error(err, "Unable to fetch the Route")
			return err
		}
	}

	// Reconcile the route spec if it has been manually modified
	if !justCreated && !CompareNotebookRoutes(*desiredRoute, *foundRoute) {
		log.Info("Reconciling Route")
		// Retry the update operation when the ingress controller eventually
		// updates the resource version field
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// Get the last route revision
			if err := r.Get(ctx, types.NamespacedName{
				Name:      desiredRoute.Name,
				Namespace: cluster.Namespace,
			}, foundRoute); err != nil {
				return err
			}
			// Reconcile labels and spec field
			foundRoute.Spec = desiredRoute.Spec
			foundRoute.ObjectMeta.Labels = desiredRoute.ObjectMeta.Labels
			return r.Update(ctx, foundRoute)
		})
		if err != nil {
			log.Error(err, "Unable to reconcile the Route")
			return err
		}
	}

	return nil
}

func NewClusterRoute(cluster *rayv1.RayCluster) *routev1.Route {
	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				"notebook-name": cluster.Name,
			},
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind:   "Service",
				Name:   cluster.Name,
				Weight: pointer.Int32Ptr(100),
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("http-" + cluster.Name),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationPassthrough,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
			WildcardPolicy: routev1.WildcardPolicyNone,
		},
		Status: routev1.RouteStatus{
			Ingress: []routev1.RouteIngress{},
		},
	}
}

// NewClusterOAuthRoute defines the desired OAuth route object
func NewClusterOAuthRoute(cluster *rayv1.RayCluster) *routev1.Route {
	route := NewClusterRoute(cluster)
	route.Spec.To.Name = cluster.Name + "-tls"
	route.Spec.Port.TargetPort = intstr.FromString(OAuthServicePortName)
	route.Spec.TLS.Termination = routev1.TLSTerminationReencrypt
	return route
}

// ReconcileOAuthRoute will manage the creation, update and deletion of the OAuth route
// when the notebook is reconciled.
func (r *RayClusterReconciler) ReconcileOAuthRoute(
	cluster *rayv1.RayCluster, ctx context.Context) error {
	return r.reconcileRoute(cluster, ctx, NewClusterOAuthRoute)
}
