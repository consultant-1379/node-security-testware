package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_NEGATIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_NEGATIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_SNMP_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CREDENTIAL_SNMP_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.SpecificCredentialTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.SnmpV3TestSteps;

import java.util.concurrent.TimeUnit;

/**
 * Flows for credentials create/update commands.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialsFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_CREDENTIALS_CREATE = "addedNodesWithCredentialsCreate";

    @Inject
    private SpecificCredentialTestSteps specificCredentialTestSteps;
    @Inject
    private SnmpV3TestSteps snmpV3TestSteps;
    @Inject
    private CredentialTestSteps credentialTestSteps;

    /**
     * Delete NetworkElementSecurity object. Credentials create command.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsCreatePositive() {
        return flow("Credentials Create Positive Flow").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES));
    }

    /**
     * Delete NetworkElementSecurity object. Credentials update command.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsUpdatePositive() {
        return flow("Credentials Update Positive Flow").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_UPDATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.updateTest).bindTo(ADDED_NODES));
    }

    /**
     * Credentials create and check error message "credentials already defined".
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialAlreadyDefined() {
        return flow("Credentials Negative Flow credentialAlreadyDefined").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_NEGATIVE_TESTS_CSV, CREDENTIAL_NEGATIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.CRED_CREATE_WITH_PARAMETER)
                                .withParameter(SpecificCredentialTestSteps.CHECK_RESPONSE, false))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.CRED_CREATE_WITH_PARAMETER)
                                .withParameter(SpecificCredentialTestSteps.CHECK_RESPONSE, true)).withDataSources(
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.credentialAlreadyDefined).bindTo(ADDED_NODES));
    }

    /**
     * Credentials update and check error message "credentials to be defined".
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialToBeDefined() {
        return flow("Credentials Negative Flow credentialToBeDefined").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_NEGATIVE_TESTS_CSV, CREDENTIAL_NEGATIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.CRED_UPDATE_WITH_PARAMETER)
                        .withParameter(SpecificCredentialTestSteps.CHECK_RESPONSE, true))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.credentialToBeDefined).bindTo(ADDED_NODES));
    }

    /**
     * Credentials create/update and check error message.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsNegative() {
        return flow("Credentials Negative Flow credentialsNegative").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_NEGATIVE_TESTS_CSV, CREDENTIAL_NEGATIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.CRED_CREATE_WITH_PARAMETER)
                                .withParameter(SpecificCredentialTestSteps.CHECK_RESPONSE, true))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.CRED_UPDATE_WITH_PARAMETER)
                                .withParameter(SpecificCredentialTestSteps.CHECK_RESPONSE, true)).withDataSources(
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.credentialGenericError).bindTo(ADDED_NODES));
    }

    /**
     * Credentials get command.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder getCredentialsPositive() {
        return flow("Get Credentials Positive Flow getCredentialsPositive").beforeFlow(
                addNodeTypeToDataSource(CREDENTIALS_GET_POSITIVE_TESTS_CSV, CREDENTIALS_GET_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.GET_CREDENTIALS)).withDataSources(
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.DELETE_SECURITY_INFO),
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.CRED_CREATE),
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.getCredTest).bindTo(ADDED_NODES)
                                .inTestStep(SpecificCredentialTestSteps.GET_CREDENTIALS));
    }

    /**
     * Credentials get command with file.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder getCredentialsWithFilePositive() {
        return flow("Get Credentials With File Positive Flow getCredentialsWithFilePositive").beforeFlow(
                addNodeTypeToDataSource(CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE_CSV, CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE,
                        ADDED_NODES_WITH_CREDENTIALS_CREATE, NodeType.ERBS.toString()))
                .afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.GET_CREDENTIALS_WITH_FILE_NAME))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.DELETE_SECURITY_INFO),
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.CRED_CREATE),
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.getCredTest).bindTo(ADDED_NODES)
                                .inTestStep(SpecificCredentialTestSteps.GET_CREDENTIALS_WITH_FILE_NAME));
    }

    /**
     * Credentials get command negative.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder getCredentialsNegative() {
        return flow("Get Credentials Negative Flow getCredentialsNegative").beforeFlow(
                addNodeTypeToDataSource(CREDENTIALS_GET_NEGATIVE_TESTS_CSV, CREDENTIALS_GET_NEGATIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.GET_NEGATIVE_CREDENTIALS)).withDataSources(
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.DELETE_SECURITY_INFO),
                        dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.getCredTest).bindTo(ADDED_NODES)
                                .inTestStep(SpecificCredentialTestSteps.GET_NEGATIVE_CREDENTIALS));
    }

    /**
     * Credentials get command with custom role.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder getCredentialsRbacPositive() {
        return flow("Delete Security Info getCredentialsRbacPositive").beforeFlow(
                addNodeTypeToDataSource(CREDENTIAL_POSITIVE_TESTS_CSV, CREDENTIAL_POSITIVE_TESTS, ADDED_NODES_WITH_CREDENTIALS_CREATE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE)).pause(10, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .withDataSources(dataSource(ADDED_NODES_WITH_CREDENTIALS_CREATE).withFilter(PredicatesExt.createRbac).bindTo(ADDED_NODES));
    }

    /**
     * Credentials SNMPv3 create command.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsSNMPv3Create() {
        return flow("Create and get SNMPv3 AuthKey and PrivKey security parameters Positive Flow")
                .beforeFlow(
                        addNodeTypeToDataSource(CREDENTIAL_SNMP_POSITIVE_TESTS_CSV, CREDENTIAL_SNMP_POSITIVE_TESTS, ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET, NodeType.RADIO_NODE.toString()))
                .afterFlow(resetDataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET)).addTestStep(annotatedMethod(snmpV3TestSteps, SnmpV3TestSteps.SNMPV3_CREATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET).withFilter(PredicatesExt.createSNMPv3Test).bindTo(ADDED_NODES).inTestStep(SnmpV3TestSteps.SNMPV3_CREATE));
    }

    /**
     * Credentials SNMPv3 get command.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsSNMPv3Get() {
        return flow("Create and get SNMPv3 AuthKey and PrivKey security parameters Positive Flow")
                .beforeFlow(
                        addNodeTypeToDataSource(CREDENTIAL_SNMP_POSITIVE_TESTS_CSV, CREDENTIAL_SNMP_POSITIVE_TESTS, ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET, NodeType.RADIO_NODE.toString()))
                .afterFlow(resetDataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET)).addTestStep(annotatedMethod(snmpV3TestSteps, SnmpV3TestSteps.SNMPV3_GET))
                .withDataSources(dataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET).withFilter(PredicatesExt.getCredSNMPv3Test).bindTo(ADDED_NODES).inTestStep(SnmpV3TestSteps.SNMPV3_GET));
    }

    /**
     * Delete the object NES network element security and create credentials before credentials SNMP command execution.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder credentialsSNMPCreatePositive() {
        return flow("Credentials SNMP Create Positive Flow")
                .beforeFlow(
                        addNodeTypeToDataSource(CREDENTIAL_SNMP_POSITIVE_TESTS_CSV, CREDENTIAL_SNMP_POSITIVE_TESTS, ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET, NodeType.RADIO_NODE.toString()))
                .afterFlow(resetDataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET)).addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .withDataSources(dataSource(ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET).withFilter(PredicatesExt.createCredSNMPv3Test).bindTo(ADDED_NODES));
    }
}
