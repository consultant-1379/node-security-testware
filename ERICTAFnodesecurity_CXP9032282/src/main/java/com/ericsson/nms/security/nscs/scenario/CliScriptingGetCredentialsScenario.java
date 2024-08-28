package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;

import javax.inject.Inject;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.DataDriven;
import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.utils.FileFinder;
import com.ericsson.nms.security.nscs.data.CliScriptingValue;
import com.ericsson.oss.presentation.client.scripting.test.flows.ClientScriptingFlows;
import com.ericsson.oss.presentation.client.scripting.test.steps.ClientScriptingSteps;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CliScriptingGetCredentialsScenario extends TafTestBase {

    public static final String CLI_SCRIPT_CSV = "data/CliScriptGetCredentials.csv";
    public static final String SCRIPT_TO_ADD_GET_CREDENTIALS = "scriptToAddGetCredentials";
    final String defaultUsername = DataHandler.getConfiguration().getProperty("nscs.default.username", String.class);
    final String defaultPassword = DataHandler.getConfiguration().getProperty("nscs.default.password", String.class);

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;
    @Inject
    private BaseScenario baseScenario;
    @Inject
    private ClientScriptingFlows clientScriptingFlows;
    @Inject
    private TestContext context;

    /**
     * Set the name of the python virtual environment to use eg myTeamsVirtualEnv and create the test setup with nodes.
     */

    @BeforeClass
    public void setupCliScripting() {
        context.setAttribute(ClientScriptingSteps.KEY_VENV, "myTeamsVirtualEnv");
        context.addDataSource(SCRIPT_TO_ADD_GET_CREDENTIALS, fromCsv(CLI_SCRIPT_CSV));
    }


    /*
     * Execute the getCredentials for nodes. Test script takes url/username/password as first three arguments
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_CredentialsPositiveScenarios")
    @DataDriven(name = SCRIPT_TO_ADD_GET_CREDENTIALS)
    public void getCredentials(@Input(SCRIPT_TO_ADD_GET_CREDENTIALS) final CliScriptingValue value) {

        final TestScenario scenario = scenario("Execute user script scenario")

                .addFlow(loginlogoutFlow.loginDefaultUser()).addFlow(clientScriptingFlows.setupClientScriptingVenv())
                .addFlow(clientScriptingFlows.executeScript(FileFinder.findFile(value.getScriptFile()).get(0),
                        String.format("https://%s", HostConfigurator.getApache().getIp()), defaultUsername, defaultPassword, value.getScriptParams()))
                .addFlow(loginlogoutFlow.logout()).addFlow(loginlogoutFlow.closeTool()).build();
        baseScenario.executeScenario(scenario);
    }
}
