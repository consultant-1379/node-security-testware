package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.CredentialsFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class GetCredentialsScenario extends TafTestBase {

    private static final String TITLE_POSITIVE = "Get nodes credentials - positive scenarios";
    private static final String TITLE_NEGATIVE = "Get nodes credentials - negative scenarios";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CredentialsFlow credentialFlow;

    @Inject
    private BaseScenario baseScenario;

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-129036_1", title = TITLE_POSITIVE)
    public void getCredentialsPositive() {
        final TestScenario scenario = scenario(TITLE_POSITIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(credentialFlow.getCredentialsPositive())
                .addFlow(credentialFlow.getCredentialsWithFilePositive())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-129036_2", title = TITLE_NEGATIVE)
    public void getCredentialsNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(credentialFlow.getCredentialsNegative())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }
}
