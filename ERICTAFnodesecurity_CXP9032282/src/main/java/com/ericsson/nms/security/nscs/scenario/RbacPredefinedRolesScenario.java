/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.SmCredentialNegativeFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * Negative scenarios for credentials create with not Administrator user.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class RbacPredefinedRolesScenario extends TafTestBase {

    private static final String TITLE_OPERATOR = "Secadm Rbac OPERATOR Scenario";
    //private static final String TITLE_SECURITY_ADMIN = "Secadm Rbac SECURITY_ADMIN Scenario";
    private static final String FIELD_TECHNICIAN = "Secadm Rbac FIELD_TECHNICIAN Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogout;

    @Inject
    private SmCredentialNegativeFlow flowNegativeCredential;

    @Inject
    private BaseScenario baseScenario;

    /**
     * Credentials create negative with OPERATOR user.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_RBAC_PredefinedRole_OPERATOR", title = TITLE_OPERATOR)
    public void secadmRbacOperator() {
        final TestScenario scenario = scenario(TITLE_OPERATOR).addFlow(loginlogout.login(PredicatesExt.cmOperatorUsers))
                .addFlow(flowNegativeCredential.cannotUseSecadmWhenRoleIsNotAdministrator()).addFlow(loginlogout.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Credentials create negative with SECURITY_ADMIN user.
     * test removed from here due to security_admin role is able to create credentials
     * (behavior introduced in 18.09 sprint)
     * TODO move this test on positive flow
     *
     @Test(enabled = true, priority = 2, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_RBAC_PredefinedRole_SECURITY_ADMIN", title = TITLE_SECURITY_ADMIN)
    public void secadmRbacSecurityAdmin() {
        final TestScenario scenario = scenario(TITLE_SECURITY_ADMIN).addFlow(loginlogout.login(PredicatesExt.cmSecurityAdminUsers))
                .addFlow(flowNegativeCredential.cannotUseSecadmWhenRoleIsNotAdministrator()).addFlow(loginlogout.logout()).build();
        baseScenario.executeScenario(scenario);
    }
     */

    /**
     * Credentials create negative with FIELD TECHNICIAN user.
     */
    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_RBAC_PredefinedRole_FIELD_TECNICHIAN", title = FIELD_TECHNICIAN)
    public void secadmRbacFieldTechnician() {
        final TestScenario scenario = scenario(FIELD_TECHNICIAN).addFlow(loginlogout.login(PredicatesExt.cmFieldTechnicianUsers))
                .addFlow(flowNegativeCredential.cannotUseSecadmWhenRoleIsNotAdministrator()).addFlow(loginlogout.logout()).build();
        baseScenario.executeScenario(scenario);
    }
}
