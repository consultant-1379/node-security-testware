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
import com.ericsson.nms.security.nscs.flow.JobIdForTrustDistributeFlow;
import com.ericsson.oss.testware.enmbase.scenarios.DebugLogger;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * A TAF scenario class to perform Job ID test in Trust Distribution command
 *
 * @author The16thFloor
 * @version x.yy, 22 September 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForTrustDistributeScenario extends TafTestBase {

    private static final String TITLE_ERBS = "JobId for Trust distribute scenario for ERBS";

    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    protected JobIdForTrustDistributeFlow flow;

    /**
     * Scenario for test Job ID creation for ERBS node type after Certificate Issue command
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-145509_01", title = TITLE_ERBS)
    public void certificateErbsScenario() {
        final TestScenario scenario = scenario(TITLE_ERBS)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(flow.jobIdForTrustDistributeErbs())
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
