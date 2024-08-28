/*  ------------------------------------------------------------------------------
 *  ******************************************************************************
 *  * COPYRIGHT Ericsson 2015
 *  *
 *  * The copyright to the computer program(s) herein is the property of
 *  * Ericsson Inc. The programs may be used and/or copied only with written
 *  * permission from Ericsson Inc. or in accordance with the terms and
 *  * conditions stipulated in the agreement/contract under which the
 *  * program(s) have been supplied.
 *  ******************************************************************************
 *  ------------------------------------------------------------------------------
 */
package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.shareDataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.FM_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.LCM_LICS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.scenario.TestScenarios;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.nms.security.nscs.datasource.UsersToCreateDataSource;
import com.ericsson.oss.testware.fm.netsim.impl.flows.NodeCommandsFlows;
import com.ericsson.oss.testware.lcmoperator.flows.LcmFlows;
import com.ericsson.oss.testware.nodeintegration.flows.NodeIntegrationFlows;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;

/**
 * Name: GenericFlow Description:
 *
 * @author efabgal
 */
// TODO remove all the class.
// However:
// Reuse installLicense()
// Look at Runnable beforeDeleteUsers()
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.DoNotUseThreads"})
public class SharedFlows {

    public static final Integer VUSERS_LCMADM = DataHandler.getConfiguration().getProperty("vUser.lcmadm", 1, Integer.class);

    @Inject
    protected UserManagementTestFlows userManagementFlows;
    @Inject
    private NodeIntegrationFlows nodeIntegrationFlows;
    @Inject
    private LcmFlows lcmFlows;
    @Inject
    private LoginLogoutRestFlows loginLogoutRestFlows;
    @Inject
    private NodeCommandsFlows nodeCommandsFlows;

    public static Runnable beforeDeleteUsers() {
        return new Runnable() {
            @Override
            public void run() {
                TafTestContext.getContext().addDataSource(USERS_TO_DELETE, TafTestContext.getContext().dataSource(AVAILABLE_USERS));
            }
        };
    }

    /**
     * Returns the number of nodes.
     * 
     * @return the number of nodes
     */
    public static int getNumberOfNodes() {
        return DataHandler.getConfiguration().getProperty(UsersToCreateDataSource.NUM_OF_NODES, 2, Integer.class);
    }

    public TestStepFlow loginDefaultUser() {
        return flow("Login Default User").addSubFlow(loginLogoutRestFlows.loginDefaultUser()).build();
    }

    public TestStepFlow logout() {
        return flow("Login").addSubFlow(loginLogoutRestFlows.logout()).build();
    }

    public TestStepFlow installLicense() {
        return flow("Install License").beforeFlow(TafDataSources.shareDataSource(LCM_LICS)).afterFlow(TestScenarios.resetDataSource(LCM_LICS))
                .addSubFlow(loginDefaultUser()).addSubFlow(lcmFlows.installLicense(dataSource(LCM_LICS))).addSubFlow(logout())
                .withDataSources(dataSource(LCM_LICS)).withVusers(VUSERS_LCMADM).build();
    }

    public TestStepFlow agnosticAddSyncNodes() {
        return flow("Agnostic: Add Agnostic Sync Nodes").beforeFlow(shareDataSource(NODES_TO_ADD), shareDataSource(AVAILABLE_USERS))
                .addSubFlow(loginDefaultUser()).addSubFlow(nodeIntegrationFlows.addNode()).addSubFlow(nodeIntegrationFlows.syncNode())
                .addSubFlow(logout()).withDataSources(dataSource(NODES_TO_ADD)).withVusers(getNumberOfNodes()).build();
    }

    public TestStepFlow agnosticDelNodes() {
        return flow("Agnostic: Delete agnostic Nodes").beforeFlow(TafDataSources.shareDataSource(ADDED_NODES)).addSubFlow(loginDefaultUser())
                .addSubFlow(nodeIntegrationFlows.deleteNode()).addSubFlow(logout()).withDataSources(dataSource(ADDED_NODES))
                .withVusers(getNumberOfNodes()).build();
    }

    public TestStepFlow startNodes() {
        return flow("Agnostic: Start Nodes").beforeFlow(shareDataSource(NODES_TO_ADD))
                .addSubFlow(nodeCommandsFlows.startNetsimNodesFlow().withDataSources(dataSource(FM_NODES))).withVusers(getNumberOfNodes()).build();
    }
}
