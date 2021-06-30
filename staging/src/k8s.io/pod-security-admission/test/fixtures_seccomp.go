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
	// localhostProfile := "profiles/audit.json"

	// Pods that should be valid for v1.0+.
	fixtureData_1_0 := fixtureGenerator{
		expectErrorSubstring: "seccomp profile",
		generatePass: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
		generateFail: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
	}

	// Pods that should be valid for v1.19+.
	fixtureData_1_19 := fixtureGenerator{
		expectErrorSubstring: "seccomp profile",
		generatePass: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
		generateFail: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
	}

	// Pods that should be valid for v1.21+.
	fixtureData_1_21 := fixtureGenerator{
		expectErrorSubstring: "seccomp profile",
		generatePass: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
		generateFail: func(p *corev1.Pod) []*corev1.Pod {
			return []*corev1.Pod{}
		},
	}

	registerFixtureGenerator(
		fixtureKey{level: api.LevelRestricted, version: api.MajorMinorVersion(1, 0), check: "seccomp"},
		fixtureData_1_0,
	)

	registerFixtureGenerator(
		fixtureKey{level: api.LevelRestricted, version: api.MajorMinorVersion(1, 19), check: "seccomp"},
		fixtureData_1_19,
	)

	registerFixtureGenerator(
		fixtureKey{level: api.LevelRestricted, version: api.MajorMinorVersion(1, 21), check: "seccomp"},
		fixtureData_1_21,
	)
}
