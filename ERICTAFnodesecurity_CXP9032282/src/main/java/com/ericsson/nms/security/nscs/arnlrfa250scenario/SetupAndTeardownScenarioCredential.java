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

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_CREDENTIAL;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_FIELD_TECHNICIAN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SECURITY_ADMIN;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioCredential extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("credential.nodeTypes", "ERBS,RNC,RBS,MGW,RadioNode,BSC,vBSC,SGSN-MME,"
                    + "VTFRadioNode,5GRadioNode,vPP,vRC,DSC,vTIF,CCRC,CCDM,CCPC,CCSM,CCES,SC,EDA,vSAPC,PCG,Router6672,Controller6610,PCC,SCU,ESC,Shared-CNF,vDU",
            String.class);

    public static final String CRED_CREATE = "CredCreate";
    public static final String CRED_UPDATE = "CredUpdate";
    public static final String CRED_GET = "CredentialsGet";
    public static final String CRED_CREATE_WRONG_USER = "CredCreateWrongUser";
    public static final String CRED_UPDATE_WRONG_USER = "CredUpdateWrongUser";
    public static final String GET_CREDENTIAL_POSITIVE_DATASOURCE = "GetCredentialPositiveDataSource";
    public static final String GET_CREDENTIAL_NEGATIVE_DATASOURCE = "GetCredentialNegativeDataSource";
    public static final String GET_CREDENTIAL_POSITIVE_WITHFILE_DATASOURCE = "GetCredentialPositiveWithFileDataSource";
    public static final String SYNTAX_NEGATIVE_DATASOURCE = "CredentialSyntaxNegativeDataSource";

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_SECURITY_ADMIN, ROLE_CREDENTIAL, ROLE_GET_CREDENTIALS);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_FIELD_TECHNICIAN, ROLE_OAM);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioCredential rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioCredential correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    @Override
    protected boolean isSynchNodeRequested() {
        return false;
    }

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    /**
     * Overriding super class method, since more specific DataSources are needed.
     */
    @Override
    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "credential" + File.separator;
        final TestDataSource<DataRecord> errorMessage = fromCsv(path + "ExpectedMessage.csv");

        final TestDataSource<DataRecord> credCreate = fromCsv(path + "CredCreate.csv");
        context.addDataSource(CRED_CREATE, credCreate);

        final TestDataSource<DataRecord> credGet = fromCsv(path + "CredGet.csv");
        context.addDataSource(CRED_GET, credGet);

        final TestDataSource<DataRecord> credUpdate = fromCsv(path + "CredUpdate.csv");
        context.addDataSource(CRED_UPDATE, credUpdate);
        context.addDataSource(CRED_CREATE_WRONG_USER, TafDataSources.merge(credCreate, errorMessage));
        context.addDataSource(CRED_UPDATE_WRONG_USER, TafDataSources.merge(credUpdate, errorMessage));

        final TestDataSource<DataRecord> getCredentialsGetPositiveTests = fromCsv(path + "CredentialsGetPositiveTests.csv");
        ScenarioUtility.debugScope(getLogger(), getCredentialsGetPositiveTests);
        context.addDataSource(GET_CREDENTIAL_POSITIVE_DATASOURCE, getCredentialsGetPositiveTests);
        final TestDataSource<DataRecord> getCredentialsGetNegativeTests = fromCsv(path + "CredentialsGetNegativeTests.csv");
        ScenarioUtility.debugScope(getLogger(), getCredentialsGetNegativeTests);
        context.addDataSource(GET_CREDENTIAL_NEGATIVE_DATASOURCE, getCredentialsGetNegativeTests);
        final TestDataSource<DataRecord> getCredentialsGetWithFilePositiveTests = fromCsv(path + "CredentialsGetWithFilePositiveTests.csv");
        ScenarioUtility.debugScope(getLogger(), getCredentialsGetWithFilePositiveTests);
        context.addDataSource(GET_CREDENTIAL_POSITIVE_WITHFILE_DATASOURCE, getCredentialsGetWithFilePositiveTests);

        final TestDataSource<DataRecord> syntaxError = fromCsv(path + "SyntaxErrorCredentialTests.csv");
        ScenarioUtility.debugScope(getLogger(), syntaxError);
        context.addDataSource(SYNTAX_NEGATIVE_DATASOURCE, syntaxError);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
