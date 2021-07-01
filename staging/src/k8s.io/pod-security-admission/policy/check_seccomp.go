/*
Copyright 2021 The Kubernetes Authors.

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

package policy

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/pod-security-admission/api"
)

/*
The RuntimeDefault seccomp profile must be required, or allow specific additional profiles.

**Restricted Fields:**

spec.securityContext.seccompProfile.type
spec.containers[*].securityContext.seccompProfile
spec.initContainers[*].securityContext.seccompProfile

**Allowed Values:**

'runtime/default'
undefined / nil
*/

func init() {
	addCheck(CheckSeccompBaseline)
	addCheck(CheckSeccompRestricted)
}

// CheckSeccompBaseline returns a baseline level check
// that verifies the seccomp profile in 1.0+
func CheckSeccompBaseline() Check {
	return Check{
		ID:    "seccomp_baseline",
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			// {
			// 	MinimumVersion: api.MajorMinorVersion(1, 0),
			// 	CheckPod:       seccomp_baseline_1_0,
			// },
			{
				MinimumVersion: api.MajorMinorVersion(1, 19),
				CheckPod:       seccomp_baseline_1_19,
			},
		},
	}
}

// CheckSeccompRestricted returns a restricted level check
// that verifies the seccomp profile in 1.0+
func CheckSeccompRestricted() Check {
	return Check{
		ID:    "seccomp_restricted",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			// {
			// 	MinimumVersion: api.MajorMinorVersion(1, 0),
			// 	CheckPod:       seccomp_restricted_1_0,
			// },
			{
				MinimumVersion: api.MajorMinorVersion(1, 19),
				CheckPod:       seccomp_restricted_1_19,
			},
		},
	}
}

const (
	alphaAnnotationSeccompDefaultProfileName  = "seccomp.security.alpha.kubernetes.io/defaultProfileName"
	alphaAnnotationSeccompAllowedProfileNames = "seccomp.security.alpha.kubernetes.io/allowedProfileNames"
)

// seccomp_baseline_1_0 is the baseline seccomp check for v1.0+.
//
// This check ensures that the seccomp alpha annotation is not explicitly set to `unconfined`.
// func seccomp_baseline_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
// 	return CheckResult{Allowed: true}
// }

// seccomp_baseline_1_19 is the baseline seccomp check for v1.19+.
//
// Starting in this version, seccomp profile is provided in the `securityContext.seccompProfile`
// key, rather than the alpha annotation. This check ensures that the value at that key is
// not explicitly set to `Unconfined`.
func seccomp_baseline_1_19(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
	forbidden := sets.NewString()

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.SeccompProfile != nil {
			if podSpec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
				forbidden.Insert(fmt.Sprintf("pod %s", podMetadata.Name))
			}
		}
	}

	visitContainersWithPath(podSpec, field.NewPath("spec"), func(c *corev1.Container, p *field.Path) {
		if c.SecurityContext != nil {
			if c.SecurityContext.SeccompProfile != nil {
				if c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
					forbidden.Insert(fmt.Sprintf("container %s", c.Name))
				}
			}
		}
	})

	if len(forbidden) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "seccomp profile",
			ForbiddenDetail: strings.Join(forbidden.List(), ", "),
		}
	}

	return CheckResult{Allowed: true}
}

// seccomp_restricted_1_0 is the restricted seccomp check for v1.0+.
//
// This check ensures that the seccomp alpha annotation is explicitly set to `runtime/default`
// or `localhost`.
// func seccomp_restricted_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
// 	return CheckResult{Allowed: true}
// }

// seccomp_restricted_1_19 is the restricted seccomp check for v1.19+.
//
// Starting in this version, seccomp profile is provided in the `securityContext.seccompProfile`
// key, rather than the alpha annotation. This check ensures that the value at that key is
// explicitly set to `RuntimeDefault` or `Localhost`.
func seccomp_restricted_1_19(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
	forbidden := sets.NewString()

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.SeccompProfile != nil {
			if podSpec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
				forbidden.Insert("pod")
			}
		}
	}

	visitContainersWithPath(podSpec, field.NewPath("spec"), func(c *corev1.Container, p *field.Path) {
		if c.SecurityContext != nil {
			if c.SecurityContext.SeccompProfile != nil {
				if c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
					forbidden.Insert(fmt.Sprintf("container %s", c.Name))
				}
			}
		}
	})

	if len(forbidden) > 0 {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "seccomp profile",
			ForbiddenDetail: strings.Join(forbidden.List(), ", "),
		}
	}

	return CheckResult{Allowed: true}
}
