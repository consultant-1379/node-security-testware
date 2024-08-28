/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.transform;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.IscfSecurityConstants.CRED_SERV_API_NODES_CSV;
import static com.ericsson.nms.security.nscs.constants.IscfSecurityConstants.CRED_SERV_API_POSITIVE_CSV;
import static com.ericsson.nms.security.nscs.constants.IscfSecurityConstants.CRED_SERV_API_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.IscfSecurityConstants.CRED_SERV_API_USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.pool.DataPoolStrategy;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.AddRemoveNodesFlow;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.enmbase.data.ENMUser;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
import com.ericsson.oss.testware.security.gim.utility.UsersToCreate;

/**
 * @author enmadmin
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialServiceApiSetUpTearDownScenario extends TafTestBase {

    private static final Logger log = LoggerFactory.getLogger(SetUpTearDownScenario.class);

    @Inject
    private UserManagementTestFlows userManagementFlows;

    @Inject
    private LoginLogoutRestFlows loginLogoutFlow;

    @Inject
    private AddRemoveNodesFlow nodeFlow;

    @Inject
    private BaseScenario baseScenario;

    @Inject
    private TestContext context;

    @BeforeSuite(alwaysRun = true)
    public void onBeforeSuiteCredentialServiceApi() {
        log.info("****** credentialServiceApiSetUpTearDownScenario - onBeforeSuitecredentialServiceApi(): Begin... \n");
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        final String sourcePath = Utils.getSourcePath();
        log.debug("profile: " + profile);
        log.debug("sourcePath: " + sourcePath);
        log.debug("Loaded profile [{}] and sourcePath [{}] ", profile, sourcePath);
        loadCredentialServiceApiDataSourcesByProfile(sourcePath);
        if (profile.equals(SecurityConstants.PROFILE_MAINTRACK)) {
            createCredentialServiceApiSetupScenario();
            log.info("***** credentialServiceApiSetUpTearDownScenario - createCredentialServiceApiSetupScenario():  ...End. ");
        }
        log.info("***** credentialServiceApiSetUpTearDownScenario - onBeforeSuiteCredentialServiceApi():  ...End. ");
    }

    @AfterSuite(alwaysRun = true)
    public void onAfterSuiteCredentialServiceApi() {
        log.info("***** credentialServiceApiSetUpTearDownScenario - onAfterSuiteCredentialServiceApi(): Begin... \n");
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        log.debug("profile: ", profile);
        if (profile.equals(SecurityConstants.PROFILE_MAINTRACK)) {
            createCredentialServiceApiTeardownScenario();
            log.info("**** credentialServiceApiSetUpTearDownScenario - createCredentialServiceApiTeardownScenario():  ...End. \n");
        }
        log.info("****** credentialServiceApiSetUpTearDownScenario - onAfterSuiteCredentialServiceApi():  ...End. \n");
    }

    private void createCredentialServiceApiSetupScenario() {
        final TestScenario createCredentialServiceApiSetupScenario = scenario("Credential Service Api SetUp Scenario")
                .addFlow(userManagementFlows.createUser()).addFlow(loginLogoutFlow.loginDefaultUser()).addFlow(nodeFlow.addNodes())
                .addFlow(nodeFlow.confirmAddedNodes()).addFlow(loginLogoutFlow.logout()).addFlow(loginLogoutFlow.closeTool()).build();
        baseScenario.executeScenario(createCredentialServiceApiSetupScenario);
    }

    private void createCredentialServiceApiTeardownScenario() {
        final TestScenario credentialServiceApiTeardownScenario = scenario("credential Service Api TearDown Scenario")
                .addFlow(loginLogoutFlow.loginDefaultUser()).addFlow(nodeFlow.deleteNodes(PredicatesExt.deleteNodes))
                .addFlow(loginLogoutFlow.logout()).addFlow(loginLogoutFlow.closeTool()).addFlow(userManagementFlows.deleteUser()).build();
        baseScenario.executeScenario(credentialServiceApiTeardownScenario);
    }

    public void loadCredentialServiceApiDataSourcesByProfile(final String sourcePath) {
        log.info("**** credentialServiceApiSetUpTearDownScenario - loadCredentialServiceApiDataSourceByProfile(): Begin... \n");
        log.debug("Adding datasource USERS_TO_CREATE = [{}] to context, loaded from csv [{}]", USERS_TO_CREATE, CRED_SERV_API_USERS_TO_CREATE);

        context.addDataSource(USERS_TO_CREATE, shared(transform(fromCsv(CRED_SERV_API_USERS_TO_CREATE, ENMUser.class), UsersToCreate.updateUser())));

        log.debug("Added   datasource USERS_TO_CREATE = [{}] to context\n", USERS_TO_CREATE);
        log.debug("Adding datasource CRED_SERV_API_POSITIVE_TESTS = [{}] to context, loaded from csv [{}]", CRED_SERV_API_POSITIVE_TESTS,
                sourcePath + CRED_SERV_API_POSITIVE_CSV);

        context.addDataSource(CRED_SERV_API_POSITIVE_TESTS, fromCsv(sourcePath + CRED_SERV_API_POSITIVE_CSV));

        log.debug("loaded  csv [{}] CRED_SERV_API_POSITIVE_TESTS = " + CRED_SERV_API_POSITIVE_TESTS + "\n", CRED_SERV_API_POSITIVE_CSV);
        log.debug("Added  datasource CRED_SERV_API_POSITIVE_TESTS = [{}] to context\n", CRED_SERV_API_POSITIVE_TESTS);
        log.debug("Adding datasource NODES_TO_ADD = [{}] to context, loaded from csv [{}]", NODES_TO_ADD, sourcePath + CRED_SERV_API_NODES_CSV);

        context.addDataSource(NODES_TO_ADD, shared(fromCsv(CRED_SERV_API_NODES_CSV, DataPoolStrategy.STOP_ON_END)));

        log.debug("Added  datasource NODES_TO_ADD = [{}] to context\n", NODES_TO_ADD);
        log.info("*** credentialServiceApiSetUpTearDownScenario - loadCredentialServiceApiDataSourceByProfile():  ...End. ");
    }
}
