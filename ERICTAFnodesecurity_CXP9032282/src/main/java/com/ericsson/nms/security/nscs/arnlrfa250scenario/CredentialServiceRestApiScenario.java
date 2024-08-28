/*
 *  *******************************************************************************
 *  * Copyright Ericsson  2022
 *  *
 *  * The copyright to the computer program(s) herein is the property of
 *  * Ericsson Inc. The programs may be used and/or copied only with written
 *  * permission from Ericsson Inc. or in accordance with the terms and
 *  * conditions stipulated in the agreement/contract under which the
 *  * program(s) have been supplied.
 *  *******************************************************************************
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialServiceRestApiFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.inject.Inject;
import java.lang.reflect.Method;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.createTest;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.updateTest;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceRestApiTestStep.CRED_API_REST_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceRestApiTestStep.CRED_SERVICE_REST_API_CREATE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceRestApiTestStep.CRED_SERVICE_REST_API_UPDATE;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialServiceRestApiScenario extends SetupAndTeardownCredRestApiScenario {

    private static final String TITLE_CREATE = "NodeSecurity CredentialServiceApi PositiveScenario - Create Credentials";
    private static final String TITLE_UPDATE = "NodeSecurity CredentialServiceApi PositiveScenario - Update Credentials";
    private static final String USER_CANNOT_ACCESS_TO_API = "Verify ENM User cannot access to End-Point REST API without proper Role assigned";
    //private static final String TITLE_NEGATIVE = "Verify Credentials are not generated and BAD REQUEST is returned";

    @Inject
    private UtilityFlows utilityFlows;

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CredentialServiceRestApiFlow credentialServiceApiPositiveFlow;

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-121097_NodeSecurity_CredentialServiceApi_Create", title = TITLE_CREATE)
    public void credentialServiceApiPositiveCreate() {
        CredRestApiPositive_Create_Update(createTest, TITLE_CREATE, CRED_SERVICE_REST_API_CREATE);
    }

    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-121097_NodeSecurity_CredentialServiceApi_Update", title = TITLE_UPDATE)
    public void credentialServiceApiPositiveUpdate() {
        CredRestApiPositive_Create_Update(updateTest, TITLE_UPDATE, CRED_SERVICE_REST_API_UPDATE);
    }


    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "TORF-121097_NodeSecurity CredentialServiceApi_User_cannot_acces_REST_endPoint", title = USER_CANNOT_ACCESS_TO_API)
    public void credentialServiceApiUserCannotAccessToRestApi() {
        final TestScenario scenario = scenario(USER_CANNOT_ACCESS_TO_API)
                .addFlow(utilityFlows.loginFunctionalUser("2"))
                .addFlow(credentialServiceApiPositiveFlow.credServiceCreateUpdate(CRED_SERVICE_REST_API_UPDATE)
                        .withDataSources(dataSource(CRED_API_REST_DATASOURCE).withFilter(updateTest)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);

    }

    @BeforeMethod(groups = { "Acceptance" })
    public void beforeMethodWrongUserRole(final Method method) {
        if (method.getName().startsWith("credentialServiceApiUserCannotAccessToRestApi")) {
            seUptWrongUserRoleDataSources();
        }
    }

    private void CredRestApiPositive_Create_Update(final Predicate<DataRecord> filter, final String scenarioTitle, final String stepName) {
        final TestScenario scenario = scenario(scenarioTitle)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(credentialServiceApiPositiveFlow.credServiceCreateUpdate(stepName)
                        .withDataSources(dataSource(CRED_API_REST_DATASOURCE).withFilter(filter)))
                .addFlow(loginlogoutFlow.logout())
                .addFlow(utilityFlows.loginFunctionalUser("3"))
                .addFlow(credentialServiceApiPositiveFlow.credServiceApiVerify()
                        .withDataSources(dataSource(CRED_API_REST_DATASOURCE).withFilter(filter)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }
}
