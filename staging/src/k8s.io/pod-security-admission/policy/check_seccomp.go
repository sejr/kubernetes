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
	addCheck(CheckSeccomp)
}

// CheckSeccomp returns a restricted level check
// that verifies the seccomp profile in 1.0+
func CheckSeccomp() Check {
	return Check{
		ID:    "seccomp",
		Level: api.LevelRestricted,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       seccomp_1_0,
			},
			{
				MinimumVersion: api.MajorMinorVersion(1, 19),
				CheckPod:       seccomp_1_19,
			},
			{
				MinimumVersion: api.MajorMinorVersion(1, 21),
				CheckPod:       seccomp_1_21,
			},
		},
	}
}

// validSeccomp returns true if the seccomp profile is Localhost or RuntimeDefault
func validSeccomp(t corev1.SeccompProfileType) bool {
	return t == corev1.SeccompProfileTypeLocalhost ||
		t == corev1.SeccompProfileTypeRuntimeDefault
}

func seccomp_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
	forbiddenContainers := sets.NewString()
	visitContainersWithPath(podSpec, field.NewPath("spec"), func(container *corev1.Container, path *field.Path) {
		if container.SecurityContext != nil {
			if container.SecurityContext.SeccompProfile != nil {
				if !validSeccomp(container.SecurityContext.SeccompProfile.Type) {
					forbiddenContainers.Insert(container.Name)
				}
			}
		}
	})

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.SeccompProfile != nil {
			if !validSeccomp(podSpec.SecurityContext.SeccompProfile.Type) {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		} else {
			if len(forbiddenContainers) > 0 {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		}
	}

	return CheckResult{Allowed: true}
}

func seccomp_1_19(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
	forbiddenContainers := sets.NewString()
	visitContainersWithPath(podSpec, field.NewPath("spec"), func(container *corev1.Container, path *field.Path) {
		if container.SecurityContext != nil {
			if container.SecurityContext.SeccompProfile != nil {
				if !validSeccomp(container.SecurityContext.SeccompProfile.Type) {
					forbiddenContainers.Insert(container.Name)
				}
			}
		}
	})

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.SeccompProfile != nil {
			if !validSeccomp(podSpec.SecurityContext.SeccompProfile.Type) {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		} else {
			if len(forbiddenContainers) > 0 {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		}
	}

	return CheckResult{Allowed: true}
}

func seccomp_1_21(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec) CheckResult {
	forbiddenContainers := sets.NewString()
	visitContainersWithPath(podSpec, field.NewPath("spec"), func(container *corev1.Container, path *field.Path) {
		if container.SecurityContext != nil {
			if container.SecurityContext.SeccompProfile != nil {
				if !validSeccomp(container.SecurityContext.SeccompProfile.Type) {
					forbiddenContainers.Insert(container.Name)
				}
			}
		}
	})

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.SeccompProfile != nil {
			if !validSeccomp(podSpec.SecurityContext.SeccompProfile.Type) {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		} else {
			if len(forbiddenContainers) > 0 {
				return CheckResult{
					Allowed:         false,
					ForbiddenReason: "seccomp profile",
				}
			}
		}
	}

	return CheckResult{Allowed: true}
}
