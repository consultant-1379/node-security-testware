/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;

/**
 * Negative flows for credentials create with not administrator user.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SmCredentialNegativeFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_CREDENTIALS_CREATE = "addedNodesWithCredentialsCreate";

    @Inject
    CredentialTestSteps credentialTestSteps;

    /**
     * Run credentials create with not administrator user.
     *
     * @return
     */
    public TestStepFlowBuilder cannotUseSecadmWhenRoleIsNotAdministrator() {
        return flow("Verify cannot use secadm when operator user role").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.VERIFY_CANNOT_USE_SECADM_WHEN_USER_ROLE_IS_NOT_ADMINISTRATOR))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createRbac).bindTo(ADDED_NODES));
    }
}
