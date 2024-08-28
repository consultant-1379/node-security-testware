package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.CertificateReissueFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * A TAF scenario class to perform Certificate Reissue Positive and Negative tests
 *
 * @author Stefano Mazzolini, Pietro Capitani, Giuseppe Rulli
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CertificateReissueScenario extends TafTestBase {

    private static final String TITLE_POSITIVE = "Certificate Reissue Positive Scenario";
    private static final String TITLE_NEGATIVE = "Certificate Reissue Negative Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CertificateReissueFlow certificateReissueFlow;

    @Inject
    private BaseScenario baseScenario;

    /**
     * Certificate Reissue positive scenarios.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-81104_NodeSecurity_CertificateReissue_PositiveScenarios", title = TITLE_POSITIVE)
    public void certificateReissuePositive() {
        final TestScenario scenario = scenario(TITLE_POSITIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(certificateReissueFlow.certificateReissueCertTypeVerify())
                .addFlow(certificateReissueFlow.certificateReissueCaNameVerify())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Certificate Reissue negative scenarios.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-81104_NodeSecurity_CertificateReIssue_NegativeScenarios", title = TITLE_NEGATIVE)
    public void certificateReissueNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(certificateReissueFlow.certificateReissueCertType()).addFlow(certificateReissueFlow.certificateReissueCaName())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }
}
