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

    import com.ericsson.cifwk.taf.data.DataHandler;
    import com.ericsson.cifwk.taf.datasource.DataRecord;
    import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
    import com.google.common.base.Predicate;
    import org.testng.ITestContext;
    import org.testng.annotations.AfterSuite;
    import org.testng.annotations.BeforeSuite;
    import org.testng.annotations.Optional;
    import org.testng.annotations.Parameters;

    import java.util.Arrays;
    import java.util.List;

    import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;

    /**
     * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
     */
    @SuppressWarnings({"PMD.LawOfDemeter"})
    public class SetupAndTeardownBeforeTestRNLScenario extends SetupAndTeardownScenario {

        public static final String nodeTypes = DataHandler.getConfiguration().getProperty("nodeTypes", "ERBS,RNC,RBS,MGW,RadioNode,BSC,vBSC,SGSN-MME,"
                        + "VTFRadioNode,5GRadioNode,vPP,vRC,DSC,vTIF,CCRC,CCDM,CCPC,CCSM,CCES,SC,EDA,vSAPC,PCG,Router6672,Controller6610,PCC,SCU,ESC,Shared-CNF,vDU",
                String.class);


        public static List<String> positiveCustomRolesList() {
            return Arrays.asList(ROLE_NODESECURITY_ADMIN);
        }


        @Override
        protected boolean isFmSupervisionRequested() {
            return false;
        }

        @Override
        public Predicate<DataRecord> correctNodeType() {
            getLogger().debug("\n SetupAndTeardownScenarioCredential correctNodeType \n");
            return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
        }

        /**
         * Overriding super class method, since more specific DataSources are needed.
         */
        @Override
        protected void setupSpecificDataSource() {

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
