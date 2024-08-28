package com.ericsson.nms.security.nscs.scenario.infrastructure5g;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.oss.testware.security.nscs.teststeps.CreateCredentialsCliTestSteps.CREATE_CREDENTIALS_5G_INFRASTRUCTURE_TESTS_DATASOURCE;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.scenario.BaseScenario;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.nscs.flows.CreateCredentialsCliFlow;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CreateCredentialsFor5GInfrastuctureNodeScenario extends TafTestBase {

    private static final String TITLE = "Create Credentials For 5G Infrastructure Node Scenario";

    @Inject
    private LoginLogoutRestFlows loginLogoutRestFlows;

    @Inject
    private CreateCredentialsCliFlow createCredentialsCliFlow;

    @Inject
    private BaseScenario baseScenario;

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-232875_NodeSecurity_CreateCredentialsFor5GInfrastructureNode", title = TITLE)
    public void createCredentialsFor5GInfrastructureNode() {
        final TestScenario testScenario = scenario(TITLE)
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(createCredentialsCliFlow.createCredentialsFor5GInfrastructureNodeFlow()
                           .withDataSources(dataSource(CREATE_CREDENTIALS_5G_INFRASTRUCTURE_TESTS_DATASOURCE)))
                .addFlow(loginLogoutRestFlows.logout())
                .build();
        baseScenario.executeScenario(testScenario);
    }
}
