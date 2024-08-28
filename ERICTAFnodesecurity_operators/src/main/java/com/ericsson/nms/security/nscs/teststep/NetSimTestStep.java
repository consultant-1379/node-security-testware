package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.cifwk.taf.assertions.TafAsserts.assertTrue;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.NETSIM_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SSL_DEFINITION_DATASOURCE;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.NETSIM_URL;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.RM_SCRIPT;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.RM_ZIP_PATCH;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.SCRIPT;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.downloadFile;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.downloadScript;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.findAlreadyPatch;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.findRelease;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.installPatch;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.removeLocalFile;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.removeRemoteFile;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.removeRemoteScript;
import static com.ericsson.nms.security.nscs.utils.NetsimUtils.wget;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.network.util.Constants.NETSIM_NODE_OPERATOR_TYPE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.inject.Inject;

import org.hamcrest.core.IsNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.assertions.TafAsserts;
import com.ericsson.cifwk.taf.data.Host;
import com.ericsson.cifwk.taf.handlers.netsim.CommandOutput;
import com.ericsson.cifwk.taf.handlers.netsim.NetSimCommand;
import com.ericsson.cifwk.taf.handlers.netsim.NetSimResult;
import com.ericsson.cifwk.taf.handlers.netsim.commands.NetSimCommands;
import com.ericsson.cifwk.taf.handlers.netsim.domain.NetworkElement;
import com.ericsson.cifwk.taf.handlers.netsim.domain.Simulation;
import com.ericsson.cifwk.taf.tools.cli.handlers.impl.RemoteObjectHandler;
import com.ericsson.nms.security.nscs.data.NetsimPatchValue;
import com.ericsson.nms.security.nscs.data.SslDefinitionValue;
import com.ericsson.nms.security.nscs.utils.ShowSimneCommand;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.enmbase.data.NetworkNode;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.ericsson.oss.testware.network.operators.netsim.NetsimOperator;
import com.ericsson.oss.testware.network.teststeps.NetworkElementTestSteps;

/**
 * Test steps for Netsim nodes.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class NetSimTestStep {

    public static final String START_NODE_STEP = "startNode";
    public static final String STOP_NODE_STEP = "stopNode";
    public static final String COPY_SSL_DEFINITION_STEP = "copySSLDefinition";
    public static final String CREATE_SSL_DEFINITION_STEP = "createSSLDefinition";
    public static final String APPLY_SSL_DEFINITION_STEP = "applySSLDefinition";
    public static final String DELETE_SSL_DEFINITION_STEP = "deleteSSLDefinition";
    public static final String RADIO_NODE_CONFIGURATION_STEP = "radioNodeConfigurationStep";
    public static final String ERBS_NODE_CONFIGURATION_STEP = "erbsNodeConfigurationStep";

    public static final String TARGET_FOLDER_BASE = "/" + "netsim" + "/";
    public static final String CXP_RELATIVE_PATH = "/ERICTAFnodesecurity_CXP9032282/src/main/resources/";

    public static final String INSTALL_PATCHES_STEP = "installPatchesStep";
    public static final String INSTALL_PATCHES_DOWNLOAD_SCRIPT_STEP = "installPatchesDownloadScriptStep";
    public static final String INSTALL_PATCHES_REMOVE_SCRIPT_STEP = "installPatchesRemoveScriptStep";
    private static final Logger log = LoggerFactory.getLogger(NetSimTestStep.class);

    @Inject
    TestContext context;

    @Inject
    private NetsimOperator netSimOperator;

    @Inject
    private NetworkElementTestSteps networkElementTestSteps;

    /**
     * Start then node.
     *
     * @param node
     *         NetworkNode
     */
    @TestStep(id = START_NODE_STEP)
    public void startNode(@Input(ADDED_NODES) final NetworkNode node) {
        networkElementTestSteps.startNode(node.getNetworkElementId(), NETSIM_NODE_OPERATOR_TYPE, "", null);
        //        startNodeNetSim(node.getNetworkElementId());
    }

    /**
     * Stop then node.
     *
     * @param node
     *         NetworkNode
     */
    @TestStep(id = STOP_NODE_STEP)
    public void stopNode(@Input(ADDED_NODES) final NetworkNode node) {
        stopNodeNetSim(node.getNetworkElementId());
    }

    /**
     * Download script for install patches on Netsim.
     *
     * @param value
     *         NetsimPatchValue
     */
    @TestStep(id = INSTALL_PATCHES_DOWNLOAD_SCRIPT_STEP)
    public void installPatchesDownloadScript(@Input(NETSIM_TESTS) final NetsimPatchValue value) {
        try {
            final String release = findRelease();
            log.info("Found netsim release [{}]", release);
            if (release.equals(value.getReleaseName())) {
                assertTrue(downloadScript(SCRIPT));
            }
        } catch (final IOException e) {
            log.error(String.format("Caught IOException: %s", e.getMessage()));
        }
    }

    /**
     * Remove script for install patches on Netsim.
     *
     * @param value
     *         NetsimPatchValue
     */
    @TestStep(id = INSTALL_PATCHES_REMOVE_SCRIPT_STEP)
    public void installPatchesRemoveScript(@Input(NETSIM_TESTS) final NetsimPatchValue value) {
        try {
            final String release = findRelease();
            if (release.equals(value.getReleaseName())) {
                assertTrue(removeRemoteScript(RM_SCRIPT));
            }
        } catch (final IOException e) {
            log.error(String.format("Caught IOException: %s", e.getMessage()));
        }
    }

    /**
     * Install patches on Netsim.
     *
     * @param value
     *         NetsimPatchValue
     */
    @TestStep(id = INSTALL_PATCHES_STEP)
    public void installPatches(@Input(NETSIM_TESTS) final NetsimPatchValue value) {
        try {
            final String release = findRelease();
            final String[] items = value.getPatchName().split(",", -1);
            if (release.equals(value.getReleaseName())) {
                for (final String item : items) {
                    if (!findAlreadyPatch(item)) {
                        log.debug("Downloading patch [{}]", item);
                        wget(NETSIM_URL, item);
                        downloadFile(item);
                        assertTrue(installPatch(release, item));
                        assertTrue(findAlreadyPatch(item));
                        assertTrue(removeLocalFile(item));
                        assertTrue(removeRemoteFile(RM_ZIP_PATCH, item));
                    }
                }
            }
        } catch (final IOException e) {
            log.error(String.format("Caught IOException: %s", e.getMessage()));
        } catch (final ClassNotFoundException e) {
            log.error(String.format("Caught ClassNotFoundException: %s", e.getMessage()));
        }
    }

    /**
     * Create objects on RadioNode node.
     *
     * @param value
     *         NetworkNode
     */
    @TestStep(id = RADIO_NODE_CONFIGURATION_STEP)
    public void radioNodeConfiguration(@Input(ADDED_NODES) final NetworkNode value) {
        final String nodeNameTag = "NAME_NODE";
        final String nodeName = value.getNetworkElementId();
        NetworkElement ne = context.getAttribute(nodeName);
        if (ne == null) {
            ne = netSimOperator.getNetworkElement(value.getNetworkElementId());
            //            TafAsserts.fail(String.format("Cannot retrieve NE [%s]", nodeName));
        }
        final List<NetSimCommand> commands = new ArrayList<>();
        final List<String> netsimParams = Arrays.asList("ManagedElement=NAME_NODE,SystemFunctions=1,SecM=1,CertM=1,CertMCapabilities=1",
                "enrollmentSupport (seq(enum(RcscertM:EnrollmentSupport)))=3", "",
                "ManagedElement=NAME_NODE,SystemFunctions=1,SecM=1,CertM=1,TrustedCertificate=1", "", "");
        for (int i = 0; i < netsimParams.size(); i += 3) {
            if (i == NetsimActions.SET_ATTRIBUTE.getAction()) {
                final String mo = netsimParams.get(i).replaceAll(nodeNameTag, nodeName);
                final String attributes = netsimParams.get(i + 1);
                commands.add(NetSimCommands.setmoattribute(mo, attributes));
            } else if (i == NetsimActions.DELETE_MO.getAction()) {
                final String moid = netsimParams.get(i).replaceAll(nodeNameTag, nodeName);
                commands.add(NetSimCommands.deletemo(moid));
            }
        }
        ne.exec(commands);
    }

    /**
     * Create objects on ERBS node.
     *
     * @param value
     *         NetworkNode
     */
    @TestStep(id = ERBS_NODE_CONFIGURATION_STEP)
    public void erbsNodeConfiguration(@Input(NODES_TO_ADD) final NetworkNode value) {
        final String nodeName = value.getNetworkElementId();
        final NetworkElement ne = context.getAttribute(nodeName);
        TafAsserts.assertThat("Cannot retrieve NE [%s]", ne, IsNull.notNullValue());
        final List<NetSimCommand> commands = new ArrayList<>();
        final List<String> netsimParamsCreatemo = Arrays
                .asList("ManagedElement=1,IpSystem=1", "IpAccessHostEt", "1", "ManagedElement=1,IpSystem=1", "IpAccessHostEt", "2",
                        "ManagedElement=1,IpSystem=1", "IpAccessSctp", "1", "ManagedElement=1,IpSystem=1", "VpnInterface", "1",
                        "ManagedElement=1,IpSystem=1", "IpSec", "1", "ManagedElement=1", "ENodeBFunction", "1", "ManagedElement=1,TransportNetwork=1",
                        "Sctp", "1");
        final List<String> netsimParamsSetmo = Arrays
                .asList("ManagedElement=1,ENodeBFunction=1", "sctpRef (moref)=ManagedElement=1,TransportNetwork=1,Sctp=1",
                        "ManagedElement=1,IpSystem=1,IpAccessHostEt=1",
                        "ipInterfaceMoRef (moref)=ManagedElement=1,IpSystem=1,VpnInterface=1 || ipAddress=1.2.3.4",
                        "ManagedElement=1,IpSystem=1,IpAccessHostEt=2", "ipAddress=1.2.3.6", "ManagedElement=1,IpSystem=1,IpAccessSctp=1",
                        "ipAccessHostEtRef1 (moref)=ManagedElement=1,IpSystem=1,IpAccessHostEt=1", "ManagedElement=1,IpSystem=1,VpnInterface=1",
                        "ipAccessHostEtRef (moref)=ManagedElement=1,IpSystem=1,IpAccessHostEt=2", "ManagedElement=1,TransportNetwork=1,Sctp=1",
                        "ipAccessSctpRef (moref)=ManagedElement=1,IpSystem=1,IpAccessSctp=1");
        for (int i = 0; i < netsimParamsCreatemo.size(); i += 3) {
            final String parentid = netsimParamsCreatemo.get(i);
            final String type = netsimParamsCreatemo.get(i + 1);
            final String name = netsimParamsCreatemo.get(i + 2);
            commands.add(NetSimCommands.createmo(parentid, type, name, 1));
        }
        for (int i = 0; i < netsimParamsSetmo.size(); i += 2) {
            final String mo = netsimParamsCreatemo.get(i);
            final String attributes = netsimParamsCreatemo.get(i + 1);
            commands.add(NetSimCommands.setmoattribute(mo, attributes));
        }
        final NetSimResult check = ne.exec(NetSimCommands.getmoid("ManagedElement=1,IpSystem=1,IpSec=1"));
        if (check.getRawOutput().contains("Invalid MO")) {
            final NetSimResult result = ne.exec(commands);
            assertTrue(parseNetsimResult(result, "IpSec").contains("OK"));
        } else {
            log.info("Ipsec already present for node [{}]", nodeName);
        }
    }

    private String parseNetsimResult(final NetSimResult result, final String expectedWord) {
        String matchLine = "";
        final CommandOutput[] coList = result.getOutput();
        for (final CommandOutput co : coList) {
            final String extractString = co.getRawOutput();
            if (extractString.contains(expectedWord)) {
                matchLine = extractString;
                break;
            }
        }
        return matchLine;
    }

    private boolean netsimResultContains(final NetSimResult result, final String expectedWord) {
        final CommandOutput[] coList = result.getOutput();
        for (final CommandOutput co : coList) {
            final String rawOutput = co.getRawOutput();
            if (rawOutput.contains(expectedWord)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Create Ssl Definition
     *
     * @param value
     *         SslDefinitionValue
     */
    @TestStep(id = CREATE_SSL_DEFINITION_STEP)
    public void createSSLDefinition(@Input(SSL_DEFINITION_DATASOURCE) final SslDefinitionValue value) {
        final List<NetSimCommand> commands = new ArrayList<>();
        final String hostName = findHostName(value);
        log.debug("Retrieved HostName [{}]", hostName);
        assertTrue(hostName != null);
        final Simulation simne = retrieveSimulationByNE(value);
        assertTrue(simne != null);
        final NetSimResult check = simne.exec(NetSimCommands.showSsliop(value.getSslDefinitionName()));
        if (netsimResultContains(check, "There is no Corba security definition named")) {
            log.debug("creating SslDefinition for simulation [{}]", simne.getName());
            commands.add(NetSimCommands.setssliopCreateormodify(value.getSslDefinitionName()));
            commands.add(NetSimCommands.setssliopDescription(value.getSslDefinitionDescr()));
            commands.add(NetSimCommands.setssliopClientverify(value.getSslDefinitionClientVerify()));
            commands.add(NetSimCommands.setssliopClientdepth(value.getSslDefinitionClientDepth()));
            commands.add(NetSimCommands.setssliopSerververify(value.getSslDefinitionServerVerify()));
            commands.add(NetSimCommands.setssliopServerdepth(value.getSslDefinitionServerDepth()));
            commands.add(NetSimCommands.setssliopProtocol_version(value.getSslDefinitionProtocolVersion()));
            commands.add(NetSimCommands.setssliopClientpassword(value.getSslDefinitionClientPassword()));
            commands.add(NetSimCommands.setssliopServerpassword(value.getSslDefinitionServerPassword()));
            commands.add(NetSimCommands.setssliopClientcertfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionClientCertFile())));
            commands.add(
                    NetSimCommands.setssliopClientcacertfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionClientCACertFile())));
            commands.add(NetSimCommands.setssliopClientkeyfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionClientKeyFile())));
            commands.add(NetSimCommands.setssliopServercertfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionServerCertFile())));
            commands.add(
                    NetSimCommands.setssliopServercacertfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionServerCACertFile())));
            commands.add(NetSimCommands.setssliopServerkeyfile(String.format("%s%s", TARGET_FOLDER_BASE, value.getSslDefinitionServerKeyFile())));
            commands.add(NetSimCommands.setssliopSaveForce());
            final NetSimResult result = simne.exec(commands);
            assertTrue(parseNetsimResult(result, ".setssliop createormodify").contains("OK"));
        } else {
            log.info("Ssl Definition [{}] already created", value.getSslDefinitionName());
        }
    }

    /**
     * Apply Ssl Definition
     *
     * @param value
     *         SslDefinitionValue
     */
    @TestStep(id = APPLY_SSL_DEFINITION_STEP)
    public void applySSLDefinition(@Input(SSL_DEFINITION_DATASOURCE) final SslDefinitionValue value) {
        final String nodeNames = value.getSslDefinitionNodeNames();
        final List<String> nodeList = Utils.generateNodeNames(nodeNames);
        for (final String nodeName : nodeList) {
            final NetworkElement ne = findNetworkElement(nodeName);
            final String sslDefinitionName = value.getSslDefinitionName();
            if (netsimResultContains(ne.exec(new ShowSimneCommand()), "ssliop_def")) {
                log.debug("ssl definition [{}] already apply for node [{}]", sslDefinitionName, ne.getName());
                continue;
            }
            final NetSimResult result = ne
                    .exec(NetSimCommands.stop(), NetSimCommands.setSsliop("no->yes", sslDefinitionName), NetSimCommands.setSave(),
                            NetSimCommands.start());
            assertTrue(parseNetsimResult(result, "no->yes").contains("OK"));
        }
    }

    /**
     * Delete Ssl Definition
     *
     * @param value
     *         SslDefinitionValue
     */
    @TestStep(id = DELETE_SSL_DEFINITION_STEP)
    public void deleteSSLDefinition(@Input(SSL_DEFINITION_DATASOURCE) final SslDefinitionValue value) {
        final String hostName = findHostName(value);
        log.debug("Retrieved hostName [{}]", hostName);
        final Simulation simne = retrieveSimulationByNE(value);
        assertTrue(simne != null);
        final String sslDefinitionName = value.getSslDefinitionName();
        log.info("deleting SslDefinitionName [{}]", sslDefinitionName);
        simne.exec(NetSimCommands.setssliopDelete(sslDefinitionName));
    }

    /**
     * Copy certificate to Netsim.
     *
     * @param value
     *         SslDefinitionValue
     */
    @TestStep(id = COPY_SSL_DEFINITION_STEP)
    public void copySslDefinition(@Input(SSL_DEFINITION_DATASOURCE) final SslDefinitionValue value) {
        final String hostName = findHostName(value);
        log.debug("Retrieved hostName [{}]", hostName);
        assertTrue(hostName != null);
        final Host host = HostConfigurator.getHost(hostName);
        final String clientCertFileName = value.getSslDefinitionClientCertFile();
        final String clientCACertFileName = value.getSslDefinitionClientCACertFile();
        final String clientKeyFileName = value.getSslDefinitionClientKeyFile();
        log.info("clientCertFileName [{}]", clientCertFileName);
        log.info("clientCACertFileName [{}]", clientCACertFileName);
        log.info("clientKeyFileName [{}]", clientKeyFileName);
        try {
            copyFile(clientCertFileName, TARGET_FOLDER_BASE + clientCertFileName, host);
            Thread.sleep(2000);
            copyFile(clientCACertFileName, TARGET_FOLDER_BASE + clientCACertFileName, host);
            Thread.sleep(2000);
            copyFile(clientKeyFileName, TARGET_FOLDER_BASE + clientKeyFileName, host);
        } catch (final InterruptedException e1) {
            log.error(e1.getMessage(), e1);
        }
    }

    private void copyFile(final String localFilename, final String remoteFileName, final Host netsimHost) {
        try {
            final RemoteObjectHandler remoteObjectHandler = new RemoteObjectHandler(netsimHost);
            log.info("\ncopying localfile [{}] to [{}]", localFilename, remoteFileName);
            if (remoteObjectHandler.copyLocalFileToRemote(localFilename, remoteFileName)) {
                log.info("\nfilename [{}] copied successfully to netsim !!!", localFilename);
            } else {
                log.error("\nERROR copying file [{}] to [{}]", localFilename, remoteFileName);
            }
        } catch (final Exception ex) {
            log.error("\n\nCannot copy filename [{}] to netsim\n[{}]", localFilename, ex.getMessage(), ex);
        }
    }

/*    private void startNodeNetSim(final String nodeName) {
        log.info("Starting NE [{}]", nodeName);
        final NetworkElement networkElement = netSimOperator.getNetworkElement(nodeName);
        if (networkElement != null) {
            if (!networkElement.isStarted()) {
                assertTrue("Node MUST BE started", networkElement.start());
            }
            log.info("Started NE [{}]", nodeName);
            context.setAttribute(nodeName, networkElement);
        } else {
            log.info("NodeName " + nodeName + " NOT on NetSim.");
        }
    }*/

    private void stopNodeNetSim(final String nodeName) {
        log.info("Stopping NE [{}],", nodeName);
        final NetworkElement networkElement = context.getAttribute(nodeName);
        if ((networkElement != null) && (networkElement.isStarted())) {
                assertTrue("Node MUST BE stopped", networkElement.stop());
                log.info("Stopped NE [{}]", nodeName);
        }
    }

    private NetworkElement findNetworkElement(final String nodeName) {
        return context.getAttribute(nodeName);
    }

    private String findHostName(final SslDefinitionValue value) {
        final String nodeName = Utils.generateNodeNames(value.getSslDefinitionNodeNames()).get(0);
        final NetworkElement ne = findNetworkElement(nodeName);
        if (ne != null) {
            return Utils.extractHostName(ne);
        }
        return null;
    }

    private Simulation retrieveSimulationByNE(final SslDefinitionValue value) {
        final String nodeName = Utils.generateNodeNames(value.getSslDefinitionNodeNames()).get(0);
        return ((NetworkElement) context.getAttribute(nodeName)).getSimulation();
    }

    private enum NetsimActions {
        SET_ATTRIBUTE(0), DELETE_MO(3), CREATE_MO(6);

        private int code;

        NetsimActions(final int p) {
            code = p;
        }

        int getAction() {
            return code;
        }
    }
}
