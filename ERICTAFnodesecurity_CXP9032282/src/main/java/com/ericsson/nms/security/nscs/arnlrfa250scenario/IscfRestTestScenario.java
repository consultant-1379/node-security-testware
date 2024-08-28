package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.oss.testware.nodesecurity.flows.IscfRestFlow;
import com.ericsson.oss.testware.nodesecurity.utils.IscfUtils;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.inject.Inject;
import java.lang.reflect.Method;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.END_ENTITY_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_COMBO_CPP;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_IPSEC_CPP;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_OAM_CPP;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_SEC_DATA_COMBO_ECIM;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_SEC_DATA_IPSEC_ECIM;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.GENERATE_ISCF_SEC_DATA_OAM_ECIM;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_COMBO_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_IPSEC_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_OAM_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_SEC_DATA_ECIM_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_COMBO_CPP_CONTENT;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_IPSEC_CPP_CONTENT;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_OAM_CPP_CONTENT;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_SEC_DATA_COMBO_ECIM_CONTENT;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_SEC_DATA_IPSEC_ECIM_CONTENT;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.VERIFY_ISCF_SEC_DATA_OAM_ECIM_CONTENT;

@SuppressWarnings({"PMD.LawOfDemeter" , "PMD.ExcessiveImports"})
public class IscfRestTestScenario extends SetupAndTeardownIscfScenario {

    private static final String OAM_CPP_TITLE_POSITIVE = "Verify OAM ISCF is properly generated for CPP node";
    private static final String IPSEC_CPP_TITLE_POSITIVE = "Verify IPSEC ISCF is properly generated for CPP node";
    private static final String COMBINED_CPP_TITLE_POSITIVE = "Verify Combined ISCF is properly generated for CPP node";
    private static final String OAM_ECIM_TITLE_POSITIVE = "Verify OAM ISCF Sec Data is properly generated for ECIM node";
    private static final String IPSEC_ECIM_TITLE_POSITIVE = "Verify IPSEC ISCF Sec Data is properly generated for ECIM node";
    private static final String COMBINED_ECIM_TITLE_POSITIVE = "Verify Combined ISCF Sec Data is properly generated for ECIM node";
    private static final String USER_CANNOT_ACCESS_TO_API = "Verify ENM User cannot access to End-Point REST API without proper Role assigned";

    private static final String TITLE_NEGATIVE = "Verify ISCF is not generated and BAD REQUEST is returned";

    @Inject
    private IscfRestFlow iscfRestFlow;
    @Inject
    private UtilityFlows utilityFlows;
    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;



   @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_OAM_CPP", title = OAM_CPP_TITLE_POSITIVE)
    public void iscfPositive_OAM_CPP() {

           final TestScenario scenario = scenario(OAM_CPP_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_OAM_CPP, VERIFY_ISCF_OAM_CPP_CONTENT,
                        IscfUtils.Enrollment.OAM).withDataSources(dataSource(ISCF_OAM_CPP_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
           executeScenario(scenario);
    }


   @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_IPSEC_CPP", title = IPSEC_CPP_TITLE_POSITIVE)
    public void iscfPositive_IPSEC_CPP() {

           final TestScenario scenario = scenario(IPSEC_CPP_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_IPSEC_CPP, VERIFY_ISCF_IPSEC_CPP_CONTENT,
                        IscfUtils.Enrollment.IPSEC).withDataSources(dataSource(ISCF_IPSEC_CPP_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }


    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_COMBINED_CPP", title = COMBINED_CPP_TITLE_POSITIVE)
    public void iscfPositive_Combined_CPP() {

        final TestScenario scenario = scenario(COMBINED_CPP_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_COMBO_CPP, VERIFY_ISCF_COMBO_CPP_CONTENT,
                        IscfUtils.Enrollment.COMBO).withDataSources(dataSource(ISCF_COMBO_CPP_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_SEC_DATA_OAM_ECIM", title = OAM_ECIM_TITLE_POSITIVE)
    public void iscfSecDataPositive_OAM_ECIM() {

        final TestScenario scenario = scenario(OAM_ECIM_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_SEC_DATA_OAM_ECIM, VERIFY_ISCF_SEC_DATA_OAM_ECIM_CONTENT,
                        IscfUtils.Enrollment.OAM).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_SEC_DATA_COMBO_ECIM", title = COMBINED_ECIM_TITLE_POSITIVE)
    public void iscfSecDataPositive_Combined_ECIM() {

        final TestScenario scenario = scenario(COMBINED_ECIM_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_SEC_DATA_COMBO_ECIM, VERIFY_ISCF_SEC_DATA_COMBO_ECIM_CONTENT,
                        IscfUtils.Enrollment.COMBO).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }


    @Test(enabled = true, priority = 6, groups = { "Acceptance" })
    @TestId(id = "NSCS_Generate ISCF_SEC_DATA_IPSEC_ECIM", title = IPSEC_ECIM_TITLE_POSITIVE)
    public void iscfSecDataPositive_IPSEC_ECIM() {

        final TestScenario scenario = scenario(IPSEC_ECIM_TITLE_POSITIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfAndVerify(GENERATE_ISCF_SEC_DATA_IPSEC_ECIM, VERIFY_ISCF_SEC_DATA_IPSEC_ECIM_CONTENT,
                        IscfUtils.Enrollment.IPSEC).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }

    @Test(enabled = true, priority = 7, groups = { "Acceptance" })
    @TestId(id = "NSCS_ISCF_User_cannot_acces_REST_endPoint", title = USER_CANNOT_ACCESS_TO_API)
    public void userCannotAccessToRestAPI() {
        final TestScenario scenario = scenario(USER_CANNOT_ACCESS_TO_API)
                .addFlow(utilityFlows.loginFunctionalUser("2"))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_OAM_CPP).withDataSources(dataSource(ISCF_OAM_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_IPSEC_CPP).withDataSources(dataSource(ISCF_IPSEC_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_COMBO_CPP).withDataSources(dataSource(ISCF_COMBO_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_SEC_DATA_OAM_ECIM).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_SEC_DATA_IPSEC_ECIM).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_SEC_DATA_COMBO_ECIM).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(iscfRestFlow.deleteEndEntityBasic(IscfUtils.Enrollment.OAM).withDataSources(dataSource(END_ENTITY_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
   }


    @Test(enabled = true, priority = 8, groups = { "Acceptance" })
    @TestId(id = "NSCS_ISCF_NegativeScenario", title = TITLE_NEGATIVE)
    public void iscfNegativeTest() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_OAM_CPP).withDataSources(dataSource(ISCF_OAM_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_IPSEC_CPP).withDataSources(dataSource(ISCF_IPSEC_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_COMBO_CPP).withDataSources(dataSource(ISCF_COMBO_CPP_DATASOURCES)))
                .addFlow(iscfRestFlow.generateIscfBasic(GENERATE_ISCF_SEC_DATA_COMBO_ECIM).withDataSources(dataSource(ISCF_SEC_DATA_ECIM_DATASOURCES)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
   }

   @BeforeMethod(groups = { "Acceptance" })
   public void beforeMethodNegative(final Method method) {
           if (method.getName().startsWith("iscfNegativeTest")) {
                   setUpNegativeTestsDataSources();
           }
   }

    @BeforeMethod(groups = { "Acceptance" })
    public void beforeMethodWrongUserRole(final Method method) {
           if (method.getName().startsWith("userCannotAccessToRestAPI")) {
                   seUptWrongUserRoleDataSources();
           }
   }
}
