/*
 *  *******************************************************************************
 *  * Copyright Ericsson  2024
 *  *
 *  * The copyright to the computer program(s) herein is the property of
 *  * Ericsson Inc. The programs may be used and/or copied only with written
 *  * permission from Ericsson Inc. or in accordance with the terms and
 *  * conditions stipulated in the agreement/contract under which the
 *  * program(s) have been supplied.
 *  *******************************************************************************
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.createTest;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.updateTest;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceNbiTestStep.CRED_NBI_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceNbiTestStep.CRED_SERVICE_NBI_CREATE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceNbiTestStep.CRED_SERVICE_NBI_UPDATE;

import java.lang.reflect.Method;

import javax.inject.Inject;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialServiceNbiFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialServiceNbiScenario extends SetupAndTeardownCredRestApiScenario {

    private static final String TITLE_CREATE = "NodeSecurity CredentialServiceNbi PositiveScenario - Create Credentials";
    private static final String TITLE_UPDATE = "NodeSecurity CredentialServiceNbi PositiveScenario - Update Credentials";
    private static final String USER_CANNOT_ACCESS_TO_NBI = "Verify ENM User cannot access to NBI without proper Role assigned";
    private static final String INVALID_DATA_FOR_NBI = "Verify exception when invalid data passed are to NBI";

    @Inject
    private UtilityFlows utilityFlows;

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private CredentialServiceNbiFlow credentialServiceNbiFlow;

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-713325_NodeSecurity_CredentialServiceNbi_Create", title = TITLE_CREATE)
    public void credentialServiceNbiPositiveCreate()
    {
        CredRestNbiPositive_Create_Update(createTest, TITLE_CREATE, CRED_SERVICE_NBI_CREATE);
    }

    @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-713325_NodeSecurity_CredentialServiceNbi_Update", title = TITLE_UPDATE)
    public void credentialServiceNbiPositiveUpdate() {
        CredRestNbiPositive_Create_Update(updateTest, TITLE_UPDATE, CRED_SERVICE_NBI_UPDATE);
    }

    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "TORF-713325_NodeSecurity_CredentialServiceNbi_User_cannot_access_endPoint", title = USER_CANNOT_ACCESS_TO_NBI)
    public void credentialServiceNbiUserCannotAccessToNbi() {
        final TestScenario scenario = scenario(USER_CANNOT_ACCESS_TO_NBI)
                .addFlow(utilityFlows.loginFunctionalUser("5"))
                .addFlow(credentialServiceNbiFlow.credServiceNbiCreateUpdate(CRED_SERVICE_NBI_UPDATE)
                        .withDataSources(dataSource(CRED_NBI_DATASOURCE).withFilter(updateTest)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);

    }

    @Test(enabled = true, priority = 4, groups = { "Acceptance" })
    @TestId(id = "TORF-713325_NodeSecurity CredentialServiceNbi_Invalid_Data", title = INVALID_DATA_FOR_NBI)
    public void credentialServiceNbiWrongData() {
        final TestScenario scenario = scenario(INVALID_DATA_FOR_NBI)
                .addFlow(utilityFlows.loginFunctionalUser("4"))
                .addFlow(credentialServiceNbiFlow.credServiceNbiCreateUpdate(CRED_SERVICE_NBI_UPDATE)
                        .withDataSources(dataSource(CRED_NBI_DATASOURCE).withFilter(updateTest)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);

    }

    @BeforeMethod(groups = { "Acceptance" })
    public void beforeMethodWrongUserRole(final Method method) {
        if (method.getName().startsWith("credentialServiceNbiUserCannotAccessToNbi")) {
            seUptWrongUserRoleNbiDataSources();
        }
    }

    @BeforeMethod(groups = { "Acceptance" })
    public void beforeMethodNegative(final Method method) {
        if (method.getName().startsWith("credentialServiceNbiWrongData")) {
            setUpNegativeTestsDataSources();
        }
    }

    private void CredRestNbiPositive_Create_Update(final Predicate<DataRecord> filter, final String scenarioTitle, final String stepName) {
        final TestScenario scenario = scenario(scenarioTitle)
                .addFlow(utilityFlows.loginFunctionalUser("7"))
                .addFlow(credentialServiceNbiFlow.credServiceNbiCreateUpdate(stepName)
                        .withDataSources(dataSource(CRED_NBI_DATASOURCE).withFilter(filter)))
                .addFlow(loginlogoutFlow.logout())
                .build();
        executeScenario(scenario);
    }
}
