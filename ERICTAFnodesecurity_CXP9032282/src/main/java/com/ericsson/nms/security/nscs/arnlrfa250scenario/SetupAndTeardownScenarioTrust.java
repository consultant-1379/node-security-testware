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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_TRUST_OPERATOR;

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
public class SetupAndTeardownScenarioTrust extends SetupAndTeardownCertTypeScenario {


    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("trust.nodeTypes", "ERBS,MGW,RNC,RBS,RadioNode,VTFRadioNode,vRM,5GRadioNode,Router6x71,vPP,vRC,BSC,vBSC,vTIF,vSAPC,Router6672,FRONTHAUL-6020,Controller6610,SCU,ESC,Shared-CNF,vDU",
            String.class);


    public static final String TRUST_OAM = "TRUST_OAM";
    public static final String TRUST_LAAD = "TRUST_LAAD";
    public static final String TRUST_IPSEC = "TRUST_IPSEC";
    public static final String TRUST_OAM_EXPMSG = "TRUST_OAM_EXPMSG";
    public static final String TRUST_LAAD_EXPMSG = "TRUST_LAAD_EXPMSG";
    public static final String TRUST_IPSEC_EXPMSG = "TRUST_IPSEC_EXPMSG";
    public static final String TRUST_DISTRIBUTE_INVALID_CT = "TRUST_DISTRIBUTE_INVALID_CT";
    public static final String TRUST_DISTRIBUTE_INVALID_CA = "TRUST_DISTRIBUTE_INVALID_CA";
    public static final String TRUST_NODES_TO_ADD_NOT_EXISTENT_NODE = "TRUST_DISTRIBUTE_NON_EXISTENT_NODE";
    public static final String TRUST_REMOVE_NON_EXISTENT_NODE = "TRUST_REMOVE_NON_EXISTENT_NODE";
    public static final String FORCE_TRUSTCATEGORY_LAAD = "FORCE_TRUSTCATEGORY_LAAD";
    public static final String TRUST_OAM_EXPMSG_FORCED_TO_LAAD = "TRUST_OAM_EXPMSG_FORCED_TO_LAAD";

    public static final String TRUST_REMOVE_INVALID_CT = "TRUST_REMOVE_INVALID_CT";
    public static final String TRUST_REMOVE_INVALID_CA = "TRUST_REMOVE_INVALID_CA";
    public static final String TRUST_REMOVE_INVALID_SN = "TRUST_REMOVE_INVALID_SN";

    public static final String TRUST_SYNTAX_NEGATIVE = "TRUST_SYNTAX_NEGATIVE";


    public List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_TRUST_OPERATOR);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioTrust rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioTrust correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    protected void setupSpecificDataSource() {

        super.setupSpecificDataSource();

        final String path = "data" + File.separator + "feature" + File.separator + "trust" + File.separator;
        final TestDataSource<DataRecord> trustoam = fromCsv(path + "TRUST_OAM.csv");
        context.addDataSource(TRUST_OAM, trustoam);
        final TestDataSource<DataRecord> trustlaad = fromCsv(path + "TRUST_LAAD.csv");
        context.addDataSource(TRUST_LAAD, trustlaad);
        final TestDataSource<DataRecord> trustipsec = fromCsv(path + "TRUST_IPSEC.csv");
        context.addDataSource(TRUST_IPSEC, trustipsec);

        final TestDataSource<DataRecord> forceTrustCategoryLAAD = fromCsv(path + "TRUST_OAM_FORCE_TRUSTCATEGORY_LAAD.csv");
        context.addDataSource(FORCE_TRUSTCATEGORY_LAAD, forceTrustCategoryLAAD);

        final TestDataSource<DataRecord> trustDistrNegativeInvalidCT = fromCsv(path + "TRUST_DISTRIBUTE_INVALID_CT.csv");
        context.addDataSource(TRUST_DISTRIBUTE_INVALID_CT, trustDistrNegativeInvalidCT);

        final TestDataSource<DataRecord> trustDistrNegativeInvalidCA = fromCsv(path + "TRUST_DISTRIBUTE_INVALID_CA.csv");
        context.addDataSource(TRUST_DISTRIBUTE_INVALID_CA, trustDistrNegativeInvalidCA);

        final TestDataSource<DataRecord> errorMessage = fromCsv(path + "ExpectedMessage.csv");

        context.addDataSource(TRUST_OAM_EXPMSG, TafDataSources.merge(trustoam, errorMessage));
        context.addDataSource(TRUST_OAM_EXPMSG_FORCED_TO_LAAD, TafDataSources.merge(forceTrustCategoryLAAD, errorMessage));

        context.addDataSource(TRUST_LAAD_EXPMSG, TafDataSources.merge(trustlaad, errorMessage));
        context.addDataSource(TRUST_IPSEC_EXPMSG, TafDataSources.merge(trustipsec, errorMessage));

        final TestDataSource<DataRecord> trustDistrNonExistentNode = fromCsv(path + "TRUST_DISTRIBUTE_NonExistentNode.csv");
        context.addDataSource(TRUST_NODES_TO_ADD_NOT_EXISTENT_NODE, TafDataSources.merge(trustoam, trustDistrNonExistentNode));

        final TestDataSource<DataRecord> trustRemoveNegativeInvalidCT = fromCsv(path + "TRUST_REMOVE_INVALID_CT.csv");
        context.addDataSource(TRUST_REMOVE_INVALID_CT, TafDataSources.merge(trustoam, trustRemoveNegativeInvalidCT));

        final TestDataSource<DataRecord> trustRemoveNegativeInvalidCA = fromCsv(path + "TRUST_REMOVE_INVALID_CA.csv");
        context.addDataSource(TRUST_REMOVE_INVALID_CA, TafDataSources.merge(trustoam, trustRemoveNegativeInvalidCA));

        final TestDataSource<DataRecord> trustRemoveNegativeInvalidSN = fromCsv(path + "TRUST_REMOVE_INVALID_SN.csv");
        context.addDataSource(TRUST_REMOVE_INVALID_SN, TafDataSources.merge(trustoam, trustRemoveNegativeInvalidSN));

        final TestDataSource<DataRecord> trustRemoveNonExistentNode = fromCsv(path + "TRUST_REMOVE_NonExistentNode.csv");
        context.addDataSource(TRUST_REMOVE_NON_EXISTENT_NODE, TafDataSources.merge(trustoam, trustRemoveNonExistentNode));

        final TestDataSource<DataRecord> trustDistrSyntaxError = fromCsv(path + "TRUST_DISTRIBUTE_SYNTAX_ERROR.csv");
        final TestDataSource<DataRecord> trustRemSyntaxError = fromCsv(path + "TRUST_REMOVE_SYNTAX_ERROR.csv");
        context.addDataSource(TRUST_SYNTAX_NEGATIVE, TafDataSources.combine(trustDistrSyntaxError, trustRemSyntaxError) );

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), TRUST_OAM);
        ScenarioUtility.debugScope(getLogger(), TRUST_LAAD);
        ScenarioUtility.debugScope(getLogger(), TRUST_IPSEC);
        ScenarioUtility.debugScope(getLogger(), TRUST_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), TRUST_LAAD_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), TRUST_IPSEC_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), TRUST_DISTRIBUTE_INVALID_CT);
        ScenarioUtility.debugScope(getLogger(), TRUST_DISTRIBUTE_INVALID_CA);
        ScenarioUtility.debugScope(getLogger(), TRUST_NODES_TO_ADD_NOT_EXISTENT_NODE);
        ScenarioUtility.debugScope(getLogger(), TRUST_REMOVE_INVALID_CT);
        ScenarioUtility.debugScope(getLogger(), TRUST_REMOVE_INVALID_CA);
        ScenarioUtility.debugScope(getLogger(), TRUST_REMOVE_INVALID_SN);
        ScenarioUtility.debugScope(getLogger(), TRUST_REMOVE_NON_EXISTENT_NODE);
        ScenarioUtility.debugScope(getLogger(), TRUST_SYNTAX_NEGATIVE);
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
