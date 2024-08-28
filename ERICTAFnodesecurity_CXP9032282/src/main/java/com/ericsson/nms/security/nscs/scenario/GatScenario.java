package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE_OAM;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.AddRemoveNodesFlow;
import com.ericsson.nms.security.nscs.flow.GatFlows;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * Scenarios for certificate issue command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class GatScenario extends TafTestBase {

    private static final String TITLE_OAM = "Certificate Issue GAT OAM";
    private static final String TITLE_IPSEC = "Certificate Issue GAT IPSEC";
    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;
    @Inject
    private GatFlows gatFlows;
    @Inject
    private AddRemoveNodesFlow nodesFlow;
    @Inject
    private BaseScenario baseScenario;

    /**
     * Certificate Issue Scenario for GAT tests.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-104817_NodeSecurity_Certificate_Issue_Reissue_to_CPP_COM-ECIM_IPvX_nodes_certtype_OAM_GAT", title = TITLE_OAM)
    public void certificateIssueGatOam() {
        final String inputCsv = "positive_tests/GAT/inputOAM.csv";
        final TestScenario scenario = scenario(TITLE_OAM).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(nodesFlow.fmEnableAlarmSupervision(PredicatesExt.erbsByProfile)).addFlow(nodesFlow.confirmSyncNodes(PredicatesExt.byProfile))
                .addFlow(gatFlows.certificateIssueMixability(inputCsv, CERT_TYPE_OAM)).addFlow(loginlogoutFlow.logout())
                .withExceptionHandler(baseScenario.addExceptionHandler()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Certificate Issue Scenario for GAT tests.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-104817_NodeSecurity_Certificate_Issue_Reissue_to_CPP_COM-ECIM_IPvX_nodes_certtype_IPsec_GAT", title = TITLE_IPSEC)
    public void certificateIssueGatIpsec() {
        final String inputCsv = "positive_tests/GAT/inputIPSEC.csv";
        final TestScenario scenario = scenario(TITLE_IPSEC).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(nodesFlow.fmEnableAlarmSupervision(PredicatesExt.erbsByProfile)).addFlow(nodesFlow.confirmSyncNodes(PredicatesExt.byProfile))
                .addFlow(gatFlows.certificateIssueMixability(inputCsv, CERT_TYPE_IPSEC)).addFlow(loginlogoutFlow.logout())
                .withExceptionHandler(baseScenario.addExceptionHandler()).build();
        baseScenario.executeScenario(scenario);
    }
}
