/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SSH_KEY_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SSH_KEY_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_ROLE_DEFINITION_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.certIssueRbacIPsec;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.certIssueRbacOAM;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.createRbac;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.errorCredentialUsers;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.errorIpsecUsers;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.errorOamUsers;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.errorSshkeyUsers;
import static com.ericsson.nms.security.nscs.flow.CertificateIssueFlows.ADDED_NODES_WITH_CERT_ISSUE;
import static com.ericsson.nms.security.nscs.flow.CredentialsFlow.ADDED_NODES_WITH_CREDENTIALS_CREATE;
import static com.ericsson.nms.security.nscs.flow.SshKeyFlow.ADDED_NODES_WITH_SSH_KEY_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.data.RbacErrorsValue;
import com.ericsson.nms.security.nscs.teststep.SyntaxTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.flows.NodeIntegrationFlows;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.SshKeyTestSteps;

/**
 * Flows for credentials create, ssh key, certificate issue with custom roles.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class RbacRoleDefinitionFlow extends BaseFlow {

    @Inject
    SyntaxTestSteps syntaxTestSteps;
    @Inject
    CredentialTestSteps credentialTestSteps;
    @Inject
    SshKeyTestSteps sshKeyTestSteps;
    @Inject
    CertificateIssueTestSteps certificateIssueTestSteps;
    @Inject
    NodeIntegrationFlows nodeIntegrationFlows;

    /**
     * Credentials create/update with custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsCustomRoleFlow() {
        return flow("Credential Create Custom Role").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE)).pause(5, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_UPDATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Delete NetworkElementSecurity object.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsDeleteFlow() {
        return flow("Delete Security Info").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    public TestStepFlowBuilder verifySyncNodesRbac(final int vUser) {
        return flow("Verify Synch Nodes").beforeFlow(
                        addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                                NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addSubFlow(nodeIntegrationFlows.verifySynchNodeBuilder())
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(createRbac).bindTo(ADDED_NODES)).withVusers(vUser);
    }

    /**
     * Delete NetworkElementSecurity object.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder credentialsDeleteForSshKeyFlow() {
        return flow("Delete Security Info").beforeFlow(
                addNodeTypeToDataSource(SSH_KEY_POSITIVE_TESTS_CSV, SSH_KEY_POSITIVE_TESTS, ADDED_NODES_WITH_SSH_KEY_CREATE,
                        NodeType.SGSN_MME.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .withDataSources(dataSource(ADDED_NODES_WITH_SSH_KEY_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Credentials create/update for ssh key with custom role.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder credentialsCreateForSshKeyFlow() {
        return flow("Credential Create For Ssh Key").beforeFlow(
                addNodeTypeToDataSource(SSH_KEY_POSITIVE_TESTS_CSV, SSH_KEY_POSITIVE_TESTS, ADDED_NODES_WITH_SSH_KEY_CREATE,
                        NodeType.SGSN_MME.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_SSH_KEY_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Ssh Key create/update with custom role.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder sshKeyCreateCustomRoleFlow() {
        return flow("Ssh Key Create Custom Role").beforeFlow(
                addNodeTypeToDataSource(SSH_KEY_POSITIVE_TESTS_CSV, SSH_KEY_POSITIVE_TESTS, ADDED_NODES_WITH_SSH_KEY_CREATE,
                        NodeType.SGSN_MME.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_CREATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_SSH_KEY_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Ssh Key verify with custom role.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder sshKeyVerifyCustomRoleFlow() {
        return flow("Ssh Key Verify Custom Role").beforeFlow(
                addNodeTypeToDataSource(SSH_KEY_POSITIVE_TESTS_CSV, SSH_KEY_POSITIVE_TESTS, ADDED_NODES_WITH_SSH_KEY_CREATE,
                        NodeType.SGSN_MME.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_VERIFY))
                .withDataSources(dataSource(ADDED_NODES_WITH_SSH_KEY_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Ssh Key update with custom role.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder sshKeyUpdateCustomRoleFlow() {
        return flow("Ssh Key Update Custom Role").beforeFlow(
                addNodeTypeToDataSource(SSH_KEY_POSITIVE_TESTS_CSV, SSH_KEY_POSITIVE_TESTS, ADDED_NODES_WITH_SSH_KEY_CREATE,
                        NodeType.SGSN_MME.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_UPDATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_SSH_KEY_CREATE).withFilter(createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Certificate issue with OAM custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder issueOamCreateCustomRoleFlow() {
        return flow("Issue Oam Create Custom Role").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV, CERTIFICATE_ISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_ISSUE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(certIssueRbacOAM).bindTo(ADDED_NODES));
    }

    /**
     * Certificate get with OAM custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder issueOamGetCustomRoleFlow() {
        return flow("Issue Oam Get Custom Role").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV, CERTIFICATE_ISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(certIssueRbacOAM).bindTo(ADDED_NODES));
    }

    /**
     * Certificate issue with IPSEC custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder issueIpsecCreateCustomRoleFlow() {
        return flow("Issue Ipsec Create Custom Role").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV, CERTIFICATE_ISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_ISSUE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(certIssueRbacIPsec).bindTo(ADDED_NODES));
    }

    /**
     * Certificate get with IPSEC custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder issueIpsecGetCustomRoleFlow() {
        return flow("Issue Ipsec Get Custom Role").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV, CERTIFICATE_ISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(certIssueRbacIPsec).bindTo(ADDED_NODES));
    }

    /**
     * Run credentials, ssh key, certificate issue commands with custom role different from credential_role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder commandErrorCredentialCustomRoleFlow() {
        return flow("Command Error for Credential Custom Role")
                .beforeFlow(addDataSourceFromCsv(SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV, SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .afterFlow(resetDataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .addTestStep(annotatedMethod(syntaxTestSteps, SyntaxTestSteps.SYNTAX_RBAC_ERROR))
                .withDataSources(dataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS, RbacErrorsValue.class).withFilter(errorCredentialUsers));
    }

    /**
     * Run credentials, ssh key, certificate issue commands with custom role different from oam_role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder commandErrorOamCustomRoleFlow() {
        return flow("Command Error for Oam Custom Role")
                .beforeFlow(addDataSourceFromCsv(SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV, SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .afterFlow(resetDataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .addTestStep(annotatedMethod(syntaxTestSteps, SyntaxTestSteps.SYNTAX_RBAC_ERROR))
                .withDataSources(dataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS, RbacErrorsValue.class).withFilter(errorOamUsers));
    }

    /**
     * Run credentials, ssh key, certificate issue commands with custom role different from ipsec_role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder commandErrorIpsecCustomRoleFlow() {
        return flow("Command Error for Ipsec Custom Role")
                .beforeFlow(addDataSourceFromCsv(SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV, SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .afterFlow(resetDataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .addTestStep(annotatedMethod(syntaxTestSteps, SyntaxTestSteps.SYNTAX_RBAC_ERROR))
                .withDataSources(dataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS, RbacErrorsValue.class).withFilter(errorIpsecUsers));
    }

    /**
     * Run credentials, ssh key, certificate issue commands with custom role different from sshkey_role.
     *
     * @return TestStepFlowBuilder
     * @deprecated No more used it will be removed in next release.
     */
    @Deprecated
    public TestStepFlowBuilder commandErrorSshKeyCustomRoleFlow() {
        return flow("Command Error for Ssh Key Custom Role")
                .beforeFlow(addDataSourceFromCsv(SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV, SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .afterFlow(resetDataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS))
                .addTestStep(annotatedMethod(syntaxTestSteps, SyntaxTestSteps.SYNTAX_RBAC_ERROR))
                .withDataSources(dataSource(SYNTAX_ERROR_ROLE_DEFINITION_TESTS, RbacErrorsValue.class).withFilter(errorSshkeyUsers));
    }
}
