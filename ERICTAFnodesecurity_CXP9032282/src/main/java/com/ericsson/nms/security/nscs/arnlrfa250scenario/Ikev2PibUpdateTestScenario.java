/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import java.util.Arrays;
import java.util.List;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.oss.testware.nodesecurity.flows.PibParametersReadUpdateFlow;

import org.testng.annotations.Test;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.ENFORCED_IKEV2_PROFILE_ID;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.READPIB;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.UPDATEPIB;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.UPDATE_DEFAULT_PIB;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.IKEV2_PIB;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class Ikev2PibUpdateTestScenario extends ScenarioUtilityAgat {

    @Inject
    private PibParametersReadUpdateFlow pibParameterReadUpdateFlow;

    public static final List<String> ikev2PibParam = Arrays.asList(new String[]{ENFORCED_IKEV2_PROFILE_ID});

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void updateIkev2PibBeforeTests() {
        final TestScenario scenario = scenario("Read And Update IKev2 PibParam Before Tests")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readIkev2PibCommandFlow", READPIB, IKEV2_PIB, ikev2PibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateIkev2PibCommandFlow", UPDATEPIB, IKEV2_PIB, ikev2PibParam))
                .addFlow(loginLogoutRestFlows.logout())
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void updateIkev2PibAfterTests() {
        final TestScenario scenario = scenario("Read And Update IKev2 PibParam After Tests")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateIkev2PibCommandFlow", UPDATE_DEFAULT_PIB, IKEV2_PIB, ikev2PibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readIkev2PibCommandFlow", READPIB, IKEV2_PIB, ikev2PibParam))
                .addFlow(loginLogoutRestFlows.logout())
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }
}
