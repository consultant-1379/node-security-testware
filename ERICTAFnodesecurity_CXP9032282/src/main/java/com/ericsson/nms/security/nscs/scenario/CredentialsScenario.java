package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.CredentialsFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * Scenarios for credentials create/update command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialsScenario extends TafTestBase {

    private static final String TITLE_POSITIVE = "Credential Positive Scenario";
    private static final String TITLE_NEGATIVE = "Credential Negative Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CredentialsFlow credentialFlow;

    @Inject
    private BaseScenario baseScenario;

    /**
     * Credentials create/update positive scenario.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_CredentialsPositiveScenarios", title = TITLE_POSITIVE)
    public void credentialPositive() {
        final TestScenario scenario = scenario(TITLE_POSITIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(credentialFlow.credentialsCreatePositive())
                .addFlow(credentialFlow.credentialsUpdatePositive())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Credentials create/update negative scenario.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_CredentialsNegativeScenarios", title = TITLE_NEGATIVE)
    public void credentialNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(credentialFlow.credentialAlreadyDefined())
                .addFlow(credentialFlow.credentialToBeDefined())
                .addFlow(credentialFlow.credentialsNegative())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }
}
