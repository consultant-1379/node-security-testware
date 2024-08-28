/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.SyntaxFlows;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * @author enmadmin
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SyntaxErrorScenario extends TafTestBase {

    private static final String TITLE = "Syntax Error Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private SyntaxFlows flow;

    @Inject
    private BaseScenario baseScenario;

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_SyntaxErrorScenarios", title = TITLE)
    public void syntaxError() {
        final TestScenario scenario = scenario(TITLE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(flow.syntaxSendFlow())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }
}
