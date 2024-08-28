package com.ericsson.nms.security.nscs.scenario;

import com.ericsson.cifwk.taf.TafTestBase;

/**
 * Scenarios for Ssh Key create/update.
 */

public class SshKeyScenario extends TafTestBase {

    /*
    private static final String TITLE_POSITIVE = "Ssh Key Positive Scenario";
    private static final String TITLE_NEGATIVE = "Ssh Key Negative Scenario";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private SshKeyFlow sshKeyFlow;

    @Inject
    private BaseScenario baseScenario;
    */

    /**
     * Ssh key create/update positive scenario.
     */
    /*
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-94195_NodeSecurity_Sshkey_PositiveScenarios", title = TITLE_POSITIVE)
    public void sshKeyPositive() {
        final TestScenario scenario = scenario(TITLE_POSITIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(sshKeyFlow.sshkeyCreatePositive())
                .addFlow(sshKeyFlow.sshkeyUpdatePositive())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);
    }*/

    /**
     * Ssh key create/update negative scenario.
     */
    /*
    @Test(enabled = true, priority = 2, groups = { "Acceptance", "NSS" })
    @TestId(id = "TORF-94195_NodeSecurity_Sshkey_NegativeScenarios", title = TITLE_NEGATIVE)
    public void sshKeyNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(sshKeyFlow.sshKeyStaticError())
                .addFlow(sshKeyFlow.sshkeyAlreadyGenerated())
                .addFlow(sshKeyFlow.sshkeyNotFound())
                .addFlow(loginlogoutFlow.logout())
                .build();
        baseScenario.executeScenario(scenario);

    }*/
}
