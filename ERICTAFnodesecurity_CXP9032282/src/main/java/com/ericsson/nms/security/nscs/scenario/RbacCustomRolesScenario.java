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
import com.ericsson.nms.security.nscs.flow.CredentialsFlow;
import com.ericsson.nms.security.nscs.flow.RbacRoleDefinitionFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

/**
 * Scenarios for credentials create/update, ssh key create/update, certificate issue role base access.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class RbacCustomRolesScenario extends TafTestBase {

    private static final String TITLE_CREDENTIALS = "Secadm Rbac Role Definition Credential Scenario";
    private static final String TITLE_SSHKEY = "Secadm Rbac Role Definition Sshkey Scenario";
    private static final String TITLE_OAM = "Secadm Rbac Role Definition Oam Scenario";
    private static final String TITLE_IPSEC = "Secadm Rbac Role Definition Ipsec Scenario";
    private static final String TITLE_GET_CREDENTIALS = "Secadm Rbac GetCredentialsRbacScenario";
    private static final String TITLE_GET_SNMP_PLAIN_TEXT_CREDENTIALS = "Retrieve snmp AuthPassword and PrivPassword in plain text";

    private int vUser = 1;

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private RbacRoleDefinitionFlow roleFlow;

    @Inject
    private CredentialsFlow credentialFlow;

    @Inject
    private BaseScenario baseScenario;

    /**
     * Credentials create/update with custom role.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-48290_NodeSecurity_RBAC_CustomRole_credential_role", title = TITLE_CREDENTIALS)
    public void rbacRoleDefinitionCredential() {
        final TestScenario scenario = scenario(TITLE_CREDENTIALS)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.credentialsDeleteFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmCredentialUsers))
                .addFlow(roleFlow.credentialsCustomRoleFlow())
                .addFlow(roleFlow.commandErrorCredentialCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Ssh key create/update with custom role.
     *
     *  This Scenario has been removed since it is covered by
     *  NSCS_SSHKEY_Skyfall test suite
     *
    @Test(enabled = true, priority = 2, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-48290_NodeSecurity_RBAC_CustomRole_sshkey_role", title = TITLE_SSHKEY)
    public void rbacRoleDefinitionSshkey() {
        final TestScenario scenario = scenario(TITLE_SSHKEY)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.credentialsDeleteForSshKeyFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmCredentialUsers))
                .addFlow(roleFlow.credentialsCreateForSshKeyFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmSshkeyUsers))
                .addFlow(roleFlow.sshKeyCreateCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.sshKeyVerifyCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmSshkeyUsers))
                .addFlow(roleFlow.sshKeyUpdateCustomRoleFlow())
                .addFlow(roleFlow.commandErrorSshKeyCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }*/

    /**
     * Certificate issue OAM with custom role.
     */
    @Test(enabled = true, priority = 3, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-48290_NodeSecurity_RBAC_CustomRole_oam_role", title = TITLE_OAM)
    public void rbacRoleDefinitionOam() {
        final TestScenario scenario = scenario(TITLE_OAM)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.credentialsDeleteFlow())
                .addFlow(roleFlow.verifySyncNodesRbac(vUser))
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmOamUsers))
                .addFlow(roleFlow.issueOamCreateCustomRoleFlow())
                .addFlow(roleFlow.issueOamGetCustomRoleFlow())
                .addFlow(roleFlow.commandErrorOamCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Certificate issue IPSEC with custom role.
     */
    @Test(enabled = true, priority = 4, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-48290_NodeSecurity_RBAC_CustomRole_ipsec_role", title = TITLE_IPSEC)
    public void rbacRoleDefinitionIpsec() {
        final TestScenario scenario = scenario(TITLE_IPSEC)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.credentialsDeleteFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.cmIpsecUsers))
                .addFlow(roleFlow.issueIpsecCreateCustomRoleFlow())
                .addFlow(roleFlow.issueIpsecGetCustomRoleFlow())
                .addFlow(roleFlow.commandErrorIpsecCustomRoleFlow())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Credentials get with custom role.
     */
    @Test(enabled = true, priority = 5, groups = { "Acceptance" })
    @TestId(id = "TORF-129036_129183_1_30189", title = TITLE_GET_CREDENTIALS)
    public void rbacRoleDefinitionCredentials() {
        final TestScenario scenario = scenario(TITLE_GET_CREDENTIALS)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(roleFlow.credentialsDeleteFlow())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.getCredentialsUsers))
                .addFlow(credentialFlow.getCredentialsRbacPositive())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }

    /**
     * Credentials SNMP get with custom role.
     */
    @Test(enabled = true, priority = 6, groups = { "Acceptance" })
    @TestId(id = "TORF-228008_Q2_Functional_1", title = TITLE_GET_SNMP_PLAIN_TEXT_CREDENTIALS)
    public void rbacRoleDefinitionSNMPCredentials() {
        final TestScenario scenario = scenario(TITLE_GET_SNMP_PLAIN_TEXT_CREDENTIALS)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(credentialFlow.credentialsSNMPCreatePositive())
                .addFlow(credentialFlow.credentialsSNMPv3Create())
                .addFlow(loginlogoutFlow.logout())
                .addFlow(loginlogoutFlow.login(PredicatesExt.getCredentialsSNMPUsers))
                .addFlow(credentialFlow.credentialsSNMPv3Get())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }
}
