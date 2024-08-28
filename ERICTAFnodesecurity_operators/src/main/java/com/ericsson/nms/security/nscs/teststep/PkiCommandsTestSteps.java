package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_PROFILE_CREATION_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_PROFILE_REMOVE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_UPDATE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_PROFILE_CREATION_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_PROFILE_REMOVE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE_OAM;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NETWORK_ELEMENT_ID;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SUITE_PROFILE;
import static com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps.CERT_GET_RESULT;
import static com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps.CERT_TYPE_VALUE;
import static com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps.INPUT_CSV;
import static com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps.INPUT_DATA_SOURCE_NAME;
import static com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil.NODENAME_COLUMN_NAME;
import static com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil.SERIALNUMBER_COLUMN_NAME;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.utils.FileFinder;
import com.ericsson.nms.security.nscs.data.GetCredentialsValue;
import com.ericsson.nms.security.nscs.flow.BaseFlow;
import com.ericsson.nms.security.nscs.impl.rest.PkiCommandsImpl;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.LineDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.RowCell;
import com.ericsson.oss.services.scriptengine.spi.dtos.RowDto;
import com.ericsson.oss.testware.enm.cli.EnmCliOperatorImpl;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;
import com.ericsson.oss.testware.nodesecurity.utils.FdnNormalizer;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.security.authentication.tool.TafToolProvider;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class PkiCommandsTestSteps extends RestImpl {

    public static final String PKI_ENABLE_SHA1 = "pkiEnableSha1";
    public static final String PKI_REVOKED_CERTIFICATE = "pkiRevokedCertificate";
    public static final String PROFILEMNG_CREATE = "pfmMngCreate";
    public static final String PROFILEMNG_REMOVE = "pfmMngRemove";
    public static final String ENTITYMNG_CREATE = "etmMngCreate";
    public static final String ENTITYMNG_REMOVE = "etmMngRemove";
    public static final String ENTITYMNG_UPDATE = "etmMngUpdate";
    public static final String RETRIEVE_EE_ID = "retrieveEntityId";

    public static final String OAM_SUFFIX = "-oam";
    public static final String IPSEC_SUFFIX = "-ipsec";
    public static final String STATUS_REVOKED = "revoked";
    public static final String ENTITY_NAME_COLUMN_NAME = "Entity Name";
    private static final Logger LOGGER = LoggerFactory.getLogger(PkiCommandsTestSteps.class);
    private static final String LINE_SEPARATOR = "\n###############################################################";
    private static final String LINE_SEPARATOR_FAILURE = "\n--------------------------------------------------";

    @Inject
    private Provider<PkiCommandsImpl> pkiCommandsImpl;
    @Inject
    private Provider<EnmCliOperatorImpl> cmCliOperatorImpl;
    @Inject
    private TafToolProvider tafToolProvider;
    @Inject
    private BaseFlow baseFlow;
    @Inject
    private TestContext context;

    /**
     * getFileFromFileFinder.
     *
     * @param fileName
     *         file name to be found in the system
     *
     * @return File file
     */
    private static File getFileFromFileFinder(final String fileName) {
        File file = null;
        final Iterator<String> it = FileFinder.findFile(fileName).iterator();
        while (it.hasNext()) {
            final String strfileName = it.next();
            final Path p = Paths.get(strfileName);
            if (p.getFileName().toString().equals(fileName)) {
                file = new File(strfileName);
                // I usually have only 1 <fileName> in the list
                // but if I run TAF in a local environment I have multiple
                // instances
                // In this case I return the one present under target directory
                if (strfileName.contains("target")) {
                    break;
                }
            }
        }
        return file;
    }

    /**
     * Enable SHA1.
     */
    @TestStep(id = PKI_ENABLE_SHA1)
    public void pkiEnableSha1() {
        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final EnmCliResponse responseDto = pkiCommand.createSHA1();
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, null);
    }

    /**
     * Perform pki command to get revoked certificate of the entities and check that the each serial number is revoked.
     *
     * @param inputCsv
     *         input csv
     * @param certTypeValue
     *         cert type value
     * @param certGetResult
     *         enrollment status
     */
    @TestStep(id = PKI_REVOKED_CERTIFICATE)
    public void pkiRevokedCertificate(@Input(INPUT_CSV) final String inputCsv, @Input(CERT_TYPE_VALUE) final String certTypeValue,
            @Input(CERT_GET_RESULT) final EnmCliResponse certGetResult) {
        final List<Map<String, Object>> rows = baseFlow.fillListOfRows(inputCsv, INPUT_DATA_SOURCE_NAME, NodeType.ERBS.toString());
        for (final Map<String, Object> row : rows) {
            if (UtilContext.makeUtilContext().readSuiteProfile().equals(row.get(SUITE_PROFILE))) {
                final String nodeName = (String) row.get(NETWORK_ELEMENT_ID);
                final String entitySuffix = takeEntitySuffix(certTypeValue);
                final String entityName = nodeName + entitySuffix;
                final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
                final EnmCliResponse pkiResponseDto = pkiCommand.pkiReadStatusCertificate(entityName, STATUS_REVOKED);
                checkRevokeStatus(certGetResult, pkiResponseDto, entityName, certTypeValue);
            }
        }
    }

    private void checkRevokeStatus(final EnmCliResponse certGetResult, final EnmCliResponse pkiResponseDto, final String pkiEntity,
            final String certTypeValue) {
        final Map<String, List<String>> pkiStatusMap = SecurityUtil.listOfRows(pkiResponseDto);
        if (pkiStatusMap != null && pkiStatusMap.size() > 0) {
            final String entityName = pkiStatusMap.get(ENTITY_NAME_COLUMN_NAME).get(0);
            final String nodeName = entityName.substring(0, entityName.indexOf(takeEntitySuffix(certTypeValue)));
            final Map<String, List<String>> mapCertResult = SecurityUtil.listOfRows(certGetResult);
            int idx = 0;
            for (final String node : mapCertResult.get(NODENAME_COLUMN_NAME)) {
                if (FdnNormalizer.normalizeNodeName(node).equals(nodeName)) {
                    final String certGetSerialNumber = mapCertResult.get(SERIALNUMBER_COLUMN_NAME).get(idx);
                    LOGGER.info("\n\tchecking node name: [{}]" + "\n\tserial number from cert get: [{}]", nodeName, certGetSerialNumber);
                    for (final String pkiSn : pkiStatusMap.get(SERIALNUMBER_COLUMN_NAME)) {
                        final String pkiSnDec = String.valueOf(Long.parseLong(pkiSn, 16));
                        if (certGetSerialNumber.equals(pkiSnDec)) {
                            LOGGER.info(LINE_SEPARATOR + "\n\tSerial number [{}] REVOKED successful for node [{}]" + LINE_SEPARATOR,
                                    certGetSerialNumber, nodeName);
                            return;
                        }
                    }
                    LOGGER.info(LINE_SEPARATOR_FAILURE + "\n\tserial number [{}] NOT revoked for node [{}]" + LINE_SEPARATOR_FAILURE,
                            certGetSerialNumber, nodeName);
                }
                idx++;
            }
        } else {
            for (final String msg : SecurityUtil.listOfLines(pkiResponseDto)) {
                if (msg.toLowerCase().contains("error")) {
                    LOGGER.info(LINE_SEPARATOR_FAILURE + "\n\tfor Entity [{}] --- [{}]" + LINE_SEPARATOR_FAILURE, pkiEntity, msg);
                }
            }
        }
    }

    private String takeEntitySuffix(final String certTypeValue) {
        return CERT_TYPE_OAM.equals(certTypeValue) ? OAM_SUFFIX : IPSEC_SUFFIX;
    }

    @TestStep(id = PROFILEMNG_CREATE)
    public void pfmMngCreate(@Input(TRUST_PROFILE_CREATION_POSITIVE_TESTS) final GetCredentialsValue value) {
        //TODO vedere se si puo' rimuovere
//        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final String expectedMsg = value.getExpectedMsg();
        final File file = getFileFromFileFinder(value.getFileName());
        final String command = value.getCommand() + file;
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommandWithFile(command, file, tafToolProvider.getHttpTool());
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
    }

    @TestStep(id = PROFILEMNG_REMOVE)
    public void pfmMngRemove(@Input(TRUST_PROFILE_REMOVE_POSITIVE_TESTS) final GetCredentialsValue value) {
//        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final String expectedMsg = value.getExpectedMsg();
        final String trustProfile = value.getTrustProfile();
        final String command = value.getCommand() + trustProfile;
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommand(command, tafToolProvider.getHttpTool());
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
    }

    @TestStep(id = ENTITYMNG_CREATE)
    public void etmMngCreate(@Input(ENTITY_PROFILE_CREATION_POSITIVE_TESTS) final GetCredentialsValue value) {
//        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final String expectedMsg = value.getExpectedMsg();
        final File file = getFileFromFileFinder(value.getFileName());
        final String command = value.getCommand() + file;
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommandWithFile(command, file, tafToolProvider.getHttpTool());
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
    }

    @TestStep(id = ENTITYMNG_REMOVE)
    public void etmMngRemove(@Input(ENTITY_PROFILE_REMOVE_POSITIVE_TESTS) final GetCredentialsValue value) {
//        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final String expectedMsg = value.getExpectedMsg();
        final String entityProfile = value.getEntityProfile();
        final String command = value.getCommand() + entityProfile;
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommand(command, tafToolProvider.getHttpTool());
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
    }

    @TestStep(id = ENTITYMNG_UPDATE)
    public void etmMngUpdate(@Input(ENTITY_UPDATE_POSITIVE_TESTS) final GetCredentialsValue value) {
        final String expectedMsg = value.getExpectedMsg();
        final String xmlFile = readResourceFile("certificate/" + value.getFileName());
        final String xmlAfterSub = xmlFile.replaceAll("##EE_ID##", context.getAttribute("ENTITY_ID").toString());
        final byte[] fileContents = SecurityUtil.createByteArray(xmlAfterSub);
        final String fileName = value.getFileName();
        final PkiCommandsImpl pkiCommand = pkiCommandsImpl.get();
        final EnmCliResponse responseDto = pkiCommand.entityMngUpdate(fileName, fileContents);
        dumpResponseDto(responseDto);
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
    }

    @TestStep(id = RETRIEVE_EE_ID)
    public void retieveIdForEE() {
        LOGGER.info("\n\n ############# Retrieve the ID for End Entity ############# \n\n");
        final String command = "pkiadm etm -l -type ee";
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommand(command, tafToolProvider.getHttpTool());
        dumpResponseDto(responseDto);
        System.out.println("RESP DTO" + responseDto);
        for (final AbstractDto abstractDto : responseDto.getAllDtos()) {
            LOGGER.info("abstractDto getClassName [{}]", abstractDto.getClass().getName());
            if (abstractDto instanceof RowDto) {
                final RowDto rowDtoActual = (RowDto) abstractDto;
                final List<RowCell> actualRows = rowDtoActual.getElements();
                LOGGER.info("\nRow value:\n\t[{}]\n", actualRows);
                for (final RowCell row : actualRows) {
                    if (row.toString().contains("LTE07pERBS00002-ipsec")) {
                        final String toBeMatched = actualRows.toString();
                        final String[] token = toBeMatched.split("value:|;");
                        final String tokenToBeSet = token[1];
                        System.out.println("token " + tokenToBeSet);
                        context.setAttribute("ENTITY_ID", tokenToBeSet);
                        break;
                    }
                }
            }
        }
    }

    //TODO this is not good way to log something, as debug can be disabled, but loop will still execute.
    private void dumpResponseDto(final EnmCliResponse responseDto) {
        for (final AbstractDto abstractDto : responseDto.getAllDtos()) {
            LOGGER.debug("abstractDto getClassName [{}]", abstractDto.getClass().getName());
            if (abstractDto instanceof LineDto) {
                final LineDto lineDto = (LineDto) abstractDto;
                final String actual = lineDto.getValue();
                LOGGER.debug("\nLine value:\n\t[{}]\n", actual);
            }
            if (abstractDto instanceof RowDto) {
                final RowDto rowDtoActual = (RowDto) abstractDto;
                final List<RowCell> actualRows = rowDtoActual.getElements();
                LOGGER.debug("\nRow value:\n\t[{}]\n", actualRows);
            }
        }
        SecurityUtil.checkResponseDto(responseDto, null);
    }

    protected String readResourceFile(final String filePath) {
        final StringBuilder sb = new StringBuilder();
        String line = "";
        BufferedReader br = null;
        final InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(filePath);
        if (is != null) {
            try {
                br = new BufferedReader(new InputStreamReader(is));
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            } catch (final IOException ex) {
                System.err.println(ex.getMessage());
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (final IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }
        return sb.toString();
    }
}
