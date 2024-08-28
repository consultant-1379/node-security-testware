/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

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
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioTlsCiphersConfig contains necessary operations that must be executed before and after TLS ciphers config suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioTlsCiphersConfig extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("tlsCiphers.nodeTypes", "RadioNode",
            String.class);

    public static final String SET_CIPHER_RSA = "Set_RSA_Cipher";
    public static final String SET_CIPHER_EC = "Set_EC_Cipher";

    public static final List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioTlsCiphersConfig rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioTlsCiphersConfig correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    protected void setupSpecificDataSource() {

        final String path = "data" + File.separator + "feature" + File.separator + "ciphersConfig" + File.separator;

        final TestDataSource<DataRecord> setCipherRSACsv = fromCsv(path + "SetCipherRSA.csv");
        context.addDataSource(SET_CIPHER_RSA, setCipherRSACsv);
        final TestDataSource<DataRecord> setCipherECCsv = fromCsv(path + "SetCipherEC.csv");
        context.addDataSource(SET_CIPHER_EC, setCipherECCsv);

        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
        ScenarioUtility.debugScope(getLogger(), SET_CIPHER_RSA);
        ScenarioUtility.debugScope(getLogger(), SET_CIPHER_EC);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
