package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.oss.testware.nodesecurity.steps.SshKeyTestSteps;

/**
 * Flows for Ssh Key create/update.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SshKeyFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_SSH_KEY_CREATE = "addedNodesWithSshKeyCreate";
    //public static final String ADDED_NODES_WITH_SSH_KEY_UPDATE = "addedNodesWithSshKeyUpdate";

    // TODO remove all below code
    @Inject
    private SshKeyTestSteps sshKeyTestSteps;

    /**
     * Delete/Create credentials on the node. Start ssh key create. Check ssh key are copied to the NetworkElementSecurity.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder sshkeyCreate(final String sshKeyDs, final int vUser) {
        return flow("Ssh Key Create")
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_VERIFY))
                .withDataSources(dataSource(sshKeyDs)
                        .withFilter(PredicatesExt.createTest).bindTo(ADDED_NODES)).withVusers(vUser)
                .afterFlow(resetDataSource(sshKeyDs));
    }

    /**
     * Delete/Create credentials on the node. Start ssh key create. Check ssh keys are copied to the NetworkElementSecurity. Start ssh key update and
     * check the ssh keys are copied to the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder sshkeyUpdate(final String sshKeyDs, final int vUser) {
        return flow("Ssh Key Update")
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_CREATE))
                .addTestStep(annotatedMethod(sshKeyTestSteps, SshKeyTestSteps.SSH_KEY_VERIFY))
                .withDataSources(dataSource(sshKeyDs)
                        .withFilter(PredicatesExt.updateTest).bindTo(ADDED_NODES)) .withVusers(vUser)
                .afterFlow(resetDataSource(sshKeyDs));
    }
}
