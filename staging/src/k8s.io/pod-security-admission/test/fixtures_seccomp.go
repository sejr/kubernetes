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

package test

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/pod-security-admission/api"
)

func init() {
	localhostProfile := "profiles/audit.json"

	// Pods for baseline policy on v1.0+.
	// fixtureData_baseline_1_0 := fixtureGenerator{
	// 	expectErrorSubstring: "seccomp profile",
	// 	generatePass: func(p *corev1.Pod) []*corev1.Pod {
	// 		return []*corev1.Pod{p}
	// 	},
	// 	generateFail: func(p *corev1.Pod) []*corev1.Pod {
	// 		return []*corev1.Pod{p}
	// 	},
	// }

	// Pods for baseline policy on v1.19+.
	fixtureData_baseline_1_19 := fixtureGenerator{
		expectErrorSubstring: "seccomp profile",
		generatePass: func(p *corev1.Pod) []*corev1.Pod {
			p = ensureSeccompProfile(p)
			return []*corev1.Pod{
				// Minimum valid pod will pass.
				// securityContext.seccompProfile MAY be nil at baseline level
				p,
				// Pod with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// Pod with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
				// Container with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// Container with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.Containers[0].SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
				// InitContainer with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// InitContainer with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.Containers[0].SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
			}
		},
		generateFail: func(p *corev1.Pod) []*corev1.Pod {
			p = ensureSeccompProfile(p)
			return []*corev1.Pod{
				// Pod with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
				// Container with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
				// InitContainer with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.InitContainers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
			}
		},
	}

	// Pods for restricted policy on v1.0+.
	// fixtureData_restricted_1_0 := fixtureGenerator{
	// 	expectErrorSubstring: "seccomp profile",
	// 	generatePass: func(p *corev1.Pod) []*corev1.Pod {
	// 		return []*corev1.Pod{p}
	// 	},
	// 	generateFail: func(p *corev1.Pod) []*corev1.Pod {
	// 		return []*corev1.Pod{p}
	// 	},
	// }

	// Pods for restricted policy on v1.19+.
	fixtureData_restricted_1_19 := fixtureGenerator{
		expectErrorSubstring: "seccomp profile",
		generatePass: func(p *corev1.Pod) []*corev1.Pod {
			p = ensureSeccompProfile(p)
			return []*corev1.Pod{
				// Pod with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// Pod with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
				// Container with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// Container with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.Containers[0].SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
				// InitContainer with explicit RuntimeDefault profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeRuntimeDefault
				}),
				// InitContainer with explicit Localhost profile will pass.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
					p.Spec.Containers[0].SecurityContext.SeccompProfile.LocalhostProfile = &localhostProfile
				}),
			}
		},
		generateFail: func(p *corev1.Pod) []*corev1.Pod {
			p = ensureSeccompProfile(p)
			return []*corev1.Pod{
				// Minimum valid pod will fail.
				// securityContext.seccompProfile MUST NOT be nil at restricted level
				p,
				// Pod with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
				// Container with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.Containers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
				// InitContainer with explicit Unconfined profile will fail.
				tweak(p, func(p *corev1.Pod) {
					p.Spec.InitContainers[0].SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
				}),
			}
		},
	}

	// fixture generators for baseline policy

	// registerFixtureGenerator(
	// 	fixtureKey{level: api.LevelBaseline, version: api.MajorMinorVersion(1, 0), check: "seccomp_baseline"},
	// 	fixtureData_baseline_1_0,
	// )

	registerFixtureGenerator(
		fixtureKey{level: api.LevelBaseline, version: api.MajorMinorVersion(1, 19), check: "seccomp_baseline"},
		fixtureData_baseline_1_19,
	)

	// fixture generators for restricted policy

	// registerFixtureGenerator(
	// 	fixtureKey{level: api.LevelRestricted, version: api.MajorMinorVersion(1, 0), check: "seccomp_restricted"},
	// 	fixtureData_restricted_1_0,
	// )

	registerFixtureGenerator(
		fixtureKey{level: api.LevelRestricted, version: api.MajorMinorVersion(1, 19), check: "seccomp_restricted"},
		fixtureData_restricted_1_19,
	)
}
