package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_POSITIVE_TESTS_RFA250_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_AFTER;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_BEFORE;

import javax.inject.Inject;

import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.TafDataSourceDefinitionBuilder;
import com.ericsson.cifwk.taf.scenario.api.TestStepDefinition;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.BaseFlow;
import com.ericsson.nms.security.nscs.flow.CertificateIssueFlows;
import com.ericsson.nms.security.nscs.teststep.GenericTestSteps;
import com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;

/**
 * Scenarios for certificate issue command.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.UseObjectForClearerAPI"})
public class CertificateIssueScenario extends TafTestBase {

    public static final String ADDED_NODES_WITH_CERT_ISSUE = "addedNodesWithCertIssue";
    private static final String TITLE_POSITIVE = "Certificate Positive Scenario";
    private static final String TITLE_NEGATIVE = "Certificate Negative Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CertificateIssueFlows certificateIssueFlow;

    @Inject
    private CertificateIssueTestSteps certificateIssueTestSteps;

    @Inject
    private SpecificIssueTestSteps specificIssueTestSteps;

    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;

    @Inject
    private BaseScenario baseScenario;

    @Inject
    private BaseFlow baseFlow;

    @Inject
    private GenericTestSteps genericTestSteps;

    @Inject
    private TestContext context;

    /**
     * Certificate Issue Scenario starts the certificate issue flow.
     */
    @Parameters({ "isRunningInRFA250" })
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "RFA250", "NSS" })
    @TestSuite
    public void certificateIssuePositive(final boolean isRunningInRFA250) {
        final Predicate<DataRecord> certIssueByProfile;
        final String certificate_issue_positive_tests_csv;
        certIssueByProfile = PredicatesExt.certIssueByProfile;
        if (isRunningInRFA250) {
            certificate_issue_positive_tests_csv = CERTIFICATE_ISSUE_POSITIVE_TESTS_RFA250_CSV;
        } else {
            certificate_issue_positive_tests_csv = CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV;
        }
        final TestScenario scenario = dataDrivenScenario(TITLE_POSITIVE).addFlow(loginlogoutFlow.loginDefaultUser()).addFlow(
                flow("Certificate Issue positive flow").addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.ENABLE_ALARM_SUPERVISION))
                        .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                        .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                        .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_ISSUE))
                        .addTestStep(annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_CERT_ISSUE)
                                .withParameter(ADDED_NODES, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_ISSUE))
                                .withParameter(JobIdMonitorTestSteps.Parameter.FUNCTIONALITY, JobIdMonitorTestSteps.Functionality.ISSUE))
                        .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_AFTER))
                        .addTestStep(findTestStepDefinition())).withScenarioDataSources(
                fillDataSource(certificate_issue_positive_tests_csv, CERTIFICATE_ISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString()).withFilter(certIssueByProfile).bindTo(ADDED_NODES)).addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    private TestStepDefinition findTestStepDefinition() {
        return SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile()) ?
                certificateVerify() :
                certificateFullVerify();
    }

    private TestStepDefinition certificateVerify() {
        return annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_VERIFY)
                .withParameter(ENROLL_STATE_BEFORE, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                .withParameter(ENROLL_STATE_AFTER, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_AFTER));
    }

    private TestStepDefinition certificateFullVerify() {
        return annotatedMethod(specificIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_VERIFY)
                .withParameter(ENROLL_STATE_BEFORE, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                .withParameter(ENROLL_STATE_AFTER, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_AFTER));
    }

    /**
     * Certificate Issue Negative Scenario starts the certificate issue flow.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_CertificateIssue_NegativeScenarios", title = TITLE_NEGATIVE)
    public void certificateIssueNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(certificateIssueFlow.certificateIssueNegative()).addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    private TafDataSourceDefinitionBuilder fillDataSource(final String inputCsv, final String inputDataSourceName, final String outputDataSourceName,
            final String defaultNodeType) {
        context.addDataSource(outputDataSourceName,
                TestDataSourceFactory.createDataSource(baseFlow.fillListOfRows(inputCsv, inputDataSourceName, defaultNodeType)));
        return new TafDataSourceDefinitionBuilder(outputDataSourceName, DataRecord.class);
    }
}
