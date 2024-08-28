package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler.LOGONLY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.PibFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.nms.security.nscs.flow.AddRemoveNodesFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.RoleManagementTestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class IscfAndCredApiScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(IscfAndCredApiScenarioUtility.class);
    private static final String nodeOperatorType = "nodeOperatorType";

    @Inject
    private UserManagementTestFlows userManagementFlows;

    @Inject
    private AddRemoveNodesFlow addRemoveNodesFlow;

    @Inject
    private LoginLogoutRestFlows loginLogoutFlow;

    @Inject
    private RoleManagementTestFlows roleManagementTestFlows;

    @Inject
    protected UtilityFlows utilityFlows;

    @Inject
    private PibFlows pibFlow;

    public void setupUsers(final String setupName) {
        LOGGER.info(setupName);
        final TestScenario setupUsers = scenario(setupName)
                .addFlow(userManagementFlows.deleteUser())
                .addFlow(userManagementFlows.createUser())
                .withExceptionHandler(LOGONLY)
                .build();
        executeScenario(setupUsers);
    }

    public void setupNodes(final String setupName, final boolean isCredentialCreateRequested) {
        LOGGER.info(setupName);
        final TestScenario setupNodes = scenario(setupName)
                .addFlow(loginLogoutFlow.loginDefaultUser())
                .addFlow(isCredentialCreateRequested ?
                        utilityFlows.createNodes(PredicateUtil.netSimTestPredicate(), 1) : addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(nodeOperatorType)))
                //.addFlow(addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(nodeOperatorType)))
                .addFlow(loginLogoutFlow.logout()).build();
        executeScenario(setupNodes);
    }

    public void setupRoles(final String setupName) {
        LOGGER.info(setupName);
        final TestScenario setupRoles = scenario(setupName)
                .addFlow(roleManagementTestFlows.deleteRole())
                .addFlow(roleManagementTestFlows.createRole())
                .addFlow(pibFlow.delay(150, "- Delay after custom role creation"))
                .withExceptionHandler(LOGONLY)
                .build();
        executeScenario(setupRoles);
    }
    public void tearDownScenario(final String tearDownName, final boolean isRbacRequest) {
        LOGGER.info("\n\n **** " + tearDownName + " - Start ****");
        final TestScenario scenario = scenario(tearDownName)
                .addFlow(loginLogoutFlow.loginDefaultUser())
                .addFlow(addRemoveNodesFlow.deleteNodes(dataSource(ADDED_NODES).withFilter(nodeOperatorType)))
                .addFlow(loginLogoutFlow.logout())
                .addFlow(userManagementFlows.deleteUser())
                .addFlow(isRbacRequest ? roleManagementTestFlows.deleteRole() : flow("").build())
                .build();
        executeScenario(scenario);
        LOGGER.info("\n **** " + tearDownName + " - End ****\n");
    }

    public static TestScenarioRunner getScenarioRunner() {
        return runner().withListener(new LoggingScenarioListener()).build();
    }

    public static void executeScenario(final TestScenario scenario) {
        final TestScenarioRunner runner = getScenarioRunner();
        runner.start(scenario);
    }


}
