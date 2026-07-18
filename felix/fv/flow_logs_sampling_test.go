// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fv_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/collector/local"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// These tests verify that FlowLogsSamplingRate reaches the dataplane: when set,
// the NFLOG verdict rules gain a 1-in-N sampling match; when unset (rate 1) the
// rules are unchanged; and in eBPF mode (which collects flow logs from a ring
// buffer, not NFLOG) the match never appears. The exact rendered match strings
// are covered by unit tests in felix/iptables and felix/nftables; here we assert
// only that the match is present or absent, which is deterministic and avoids
// the kernel's iptables-save probability round-trip.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ flow log sampling tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		opts   infrastructure.TopologyOptions
		client client.Interface
		wl     *workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		// FlowLogsGoldmaneServer is what turns FlowLogsEnabled() on, which is the
		// gate for rendering NFLOG rules at all.
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress
	})

	// startTopology brings up a single-node topology with one workload endpoint so
	// that its NFLOG policy chains are rendered into the dataplane.
	startTopology := func() {
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
		infra.AddDefaultAllow()
		infrastructure.AssignIP("wl0", "10.65.0.2", tc.Felixes[0].Hostname, client)
		wl = workload.Run(tc.Felixes[0], "wl0", "default", "10.65.0.2", "8055", "tcp")
		wl.ConfigureInInfra(infra)
	}

	// dataplaneRuleset returns the full iptables/nftables ruleset from the felix
	// container. Errors are swallowed so it can be polled with Eventually.
	dataplaneRuleset := func() string {
		var out string
		if infrastructure.NFTMode() {
			out, _ = tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
		} else {
			out, _ = tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
		}
		return out
	}

	// samplingToken is the backend-specific, precision-independent marker of a
	// sampling match.
	samplingToken := func() string {
		if infrastructure.NFTMode() {
			return "numgen random"
		}
		return "statistic --mode random"
	}

	AfterEach(func() {
		if CurrentSpecReport().Failed() && len(tc.Felixes) > 0 {
			tc.Felixes[0].Exec("iptables-save", "-c")
			infra.DumpErrorData()
		}
		if wl != nil {
			wl.Stop()
		}
		tc.Stop()
		infra.Stop()
	})

	Context("with a sampling rate configured", func() {
		BeforeEach(func() {
			opts.ExtraEnvVars["FELIX_FLOWLOGSSAMPLINGRATE"] = "5"
		})

		It("adds the sampling match to NFLOG rules on the iptables/nftables dataplane", func() {
			startTopology()

			if bpfEnabled {
				// eBPF never renders NFLOG iptables rules, so the sampling match
				// must not appear regardless of the configured rate.
				Consistently(dataplaneRuleset, "3s", "1s").ShouldNot(ContainSubstring(samplingToken()))
				return
			}

			Eventually(dataplaneRuleset, "20s", "1s").Should(ContainSubstring(samplingToken()))
		})
	})

	Context("with sampling disabled (rate 1)", func() {
		BeforeEach(func() {
			opts.ExtraEnvVars["FELIX_FLOWLOGSSAMPLINGRATE"] = "1"
		})

		It("leaves NFLOG rules unchanged", func() {
			startTopology()

			if bpfEnabled {
				Consistently(dataplaneRuleset, "3s", "1s").ShouldNot(ContainSubstring(samplingToken()))
				return
			}

			// Wait for the workload's NFLOG chains to be programmed, then confirm no
			// sampling match was added.
			Eventually(dataplaneRuleset, "20s", "1s").Should(ContainSubstring("cali-tw-"))
			Expect(dataplaneRuleset()).NotTo(ContainSubstring(samplingToken()))
		})
	})
})
