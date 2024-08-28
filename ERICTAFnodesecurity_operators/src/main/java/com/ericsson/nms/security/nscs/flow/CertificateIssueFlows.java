/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_NEGATIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps;

/**
 * Certificate issue flow class.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CertificateIssueFlows extends BaseFlow {

    public static final String ADDED_NODES_WITH_CERT_ISSUE = "addedNodesWithCertIssue";

    @Inject
    private CertificateIssueTestSteps opCertificateIssueTestSteps;

    /**
     * Certificate issue flow. Start certificate issue test step.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateIssueNegative() {
        return flow("Certificate Issue Negative Flow").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_ISSUE_NEGATIVE_TESTS_CSV, CERTIFICATE_ISSUE_NEGATIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(opCertificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_ISSUE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(PredicatesExt.byProfile).bindTo(ADDED_NODES));
    }
}
