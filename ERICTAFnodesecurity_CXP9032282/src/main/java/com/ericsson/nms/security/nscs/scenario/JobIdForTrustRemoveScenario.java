package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.runner;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.nms.security.nscs.flow.JobIdForTrustRemoveFlow;
import com.ericsson.oss.testware.enmbase.scenarios.DebugLogger;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * A TAF scenario class to perform Job ID test in Trust remove command
 *
 * @author The16thFloor
 * @version x.yy, 04 October 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForTrustRemoveScenario extends TafTestBase {

    private static final String TITLE_ERBS = "JobId for Trust Remove Scenario for ERBS";
    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;
    @Inject
    private JobIdForTrustRemoveFlow jobIdForTrustRemoveFlow;

    /**
     * Scenario for test Job ID creation for ERBS node type after Trust Remove command
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-145512_01", title = TITLE_ERBS)
    public void trustRemoveErbsScenario() {
        final TestScenario scenario = scenario(TITLE_ERBS)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(jobIdForTrustRemoveFlow.jobIdForTrustRemoveERBS())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.closeTool())
                .build();
        final TestScenarioRunner runner = getScenarioRunner();
        runner.start(scenario);
    }

    private TestScenarioRunner getScenarioRunner() {
        return runner().withListener(new LoggingScenarioListener()).withListener(new DebugLogger()).build();
    }
}
