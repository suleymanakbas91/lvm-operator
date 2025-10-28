/*
Copyright © 2025 Red Hat, Inc.

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

package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Rapidast Security Scanning", Label("Rapidast"), Ordered, func() {
	const (
		testSAName               = "lvms-test-sa"
		metricsReaderClusterRole = "lvms-metrics-reader"
		lvmsRouteName            = "lvms-metrics-route"
		lvmsMetricsServiceName   = "lvms-operator-metrics-service"
	)

	var (
		testServiceAccount     *corev1.ServiceAccount
		testClusterRoleBinding *rbacv1.ClusterRoleBinding
		testRoute              *routev1.Route
		saToken                string
		hostURL                string
	)

	BeforeAll(func(ctx SpecContext) {
		By("Creating a service account for testing")
		testServiceAccount = &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testSAName,
				Namespace: installNamespace,
			},
		}
		CreateResource(ctx, testServiceAccount)

		By("Creating a cluster role binding for metrics access")
		testClusterRoleBinding = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-%s-binding", testSAName, metricsReaderClusterRole),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     metricsReaderClusterRole,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      testSAName,
					Namespace: installNamespace,
				},
			},
		}
		CreateResource(ctx, testClusterRoleBinding)

		By("Fetching the service account token")
		saToken = getServiceAccountToken(ctx, installNamespace, testSAName)
		Expect(saToken).NotTo(BeEmpty(), "Service account token should not be empty")

		By("Creating a route for the LVMS metrics service")
		// Get console URL from environment or construct host URL
		consoleURL := os.Getenv("CONSOLE_URL")
		if consoleURL == "" {
			// If CONSOLE_URL is not set, we'll construct a host URL based on cluster domain
			// This will be filled in by the Tekton pipeline or can be manually set
			consoleURL = "https://console-openshift-console.apps.example.com"
		}

		// Extract the apps domain from console URL
		// Example: https://console-openshift-console.apps.cluster.example.com -> apps.cluster.example.com
		index := strings.Index(consoleURL, ".apps")
		if index > 0 {
			hostURL = lvmsRouteName + consoleURL[index:]
		} else {
			// Fallback: use a default pattern
			hostURL = fmt.Sprintf("%s.apps.example.com", lvmsRouteName)
		}

		testRoute = &routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name:      lvmsRouteName,
				Namespace: installNamespace,
			},
			Spec: routev1.RouteSpec{
				Host: hostURL,
				To: routev1.RouteTargetReference{
					Kind: "Service",
					Name: lvmsMetricsServiceName,
				},
				Port: &routev1.RoutePort{
					TargetPort: intstr.FromString("https"),
				},
				TLS: &routev1.TLSConfig{
					Termination: routev1.TLSTerminationPassthrough,
				},
				WildcardPolicy: routev1.WildcardPolicyNone,
			},
		}
		CreateResource(ctx, testRoute)
	})

	It("should prepare rapidast configuration with host and token", Label("Rapidast"), func(ctx SpecContext) {
		By("Verifying the metrics service exists")
		metricsService := &corev1.Service{}
		Eventually(func(ctx SpecContext) error {
			return crClient.Get(ctx, types.NamespacedName{
				Name:      lvmsMetricsServiceName,
				Namespace: installNamespace,
			}, metricsService)
		}, timeout, interval).WithContext(ctx).Should(Succeed())

		By("Updating lvms-rapidast-config.yaml with host and token")
		configContent, err := os.ReadFile("../../lvms-rapidast-config.yaml")
		Expect(err).NotTo(HaveOccurred(), "Failed to read rapidast config file")

		newContent := strings.Replace(string(configContent), "$HOST", hostURL, -1)
		newContent = strings.Replace(newContent, "$BEARER_TOKEN", saToken, -1)

		err = os.WriteFile("../../lvms-rapidast-config-updated.yaml", []byte(newContent), 0644)
		Expect(err).NotTo(HaveOccurred(), "Failed to write updated rapidast config file")

		By("Rapidast configuration file prepared successfully")
		GinkgoLogr.Info("Rapidast config updated", "host", hostURL, "configFile", "lvms-rapidast-config-updated.yaml")
	})

	AfterAll(func(ctx SpecContext) {
		By("Cleaning up test resources")
		if testRoute != nil {
			DeleteResource(ctx, testRoute)
		}
		if testClusterRoleBinding != nil {
			DeleteResource(ctx, testClusterRoleBinding)
		}
		if testServiceAccount != nil {
			DeleteResource(ctx, testServiceAccount)
		}
	})
})

// getServiceAccountToken retrieves the token for a service account
func getServiceAccountToken(ctx context.Context, namespace, serviceAccountName string) string {
	GinkgoHelper()

	// Get the service account
	sa := &corev1.ServiceAccount{}
	Eventually(func(ctx SpecContext) error {
		return crClient.Get(ctx, types.NamespacedName{
			Name:      serviceAccountName,
			Namespace: namespace,
		}, sa)
	}, timeout, interval).WithContext(ctx).Should(Succeed())

	// Create a token secret for the service account
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-token", serviceAccountName),
			Namespace: namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": serviceAccountName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	// Check if secret already exists, if not create it
	err := crClient.Get(ctx, types.NamespacedName{
		Name:      tokenSecret.Name,
		Namespace: namespace,
	}, tokenSecret)

	if err != nil {
		CreateResource(ctx, tokenSecret)
	}

	// Wait for token to be populated
	Eventually(func(ctx SpecContext) bool {
		err := crClient.Get(ctx, types.NamespacedName{
			Name:      tokenSecret.Name,
			Namespace: namespace,
		}, tokenSecret)
		if err != nil {
			return false
		}
		return len(tokenSecret.Data["token"]) > 0
	}, timeout, interval).WithContext(ctx).Should(BeTrue())

	return string(tokenSecret.Data["token"])
}
