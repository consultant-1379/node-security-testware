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
import com.ericsson.nms.security.nscs.flow.JobIdForCertificateIssueFlow;
import com.ericsson.oss.testware.enmbase.scenarios.DebugLogger;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * A TAF scenario class to perform Job ID test in Certificate Issue command
 *
 * @author The16thFloor
 * @version x.yy, 22 September 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForCertificateIssueScenario extends TafTestBase {

    private static final String TITLE_ERBS = "JobId for Certificate Issue Scenario for ERBS";
    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;
    @Inject
    private JobIdForCertificateIssueFlow jobIdForCertificateIssueFlow;

    /**
     * Scenario for test Job ID creation for ERBS node type after Certificate Issue command
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-145504_01", title = TITLE_ERBS)
    public void certificateErbsScenario() {
        final TestScenario scenario = scenario(TITLE_ERBS).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(jobIdForCertificateIssueFlow.jobIdForCertIssueERBS()).addFlow(loginlogoutFlow.logout()).addFlow(loginlogoutFlow.closeTool())
                .build();
        final TestScenarioRunner runner = getScenarioRunner();
        runner.start(scenario);
    }

    private TestScenarioRunner getScenarioRunner() {
        return runner().withListener(new LoggingScenarioListener()).withListener(new DebugLogger()).build();
    }
}
