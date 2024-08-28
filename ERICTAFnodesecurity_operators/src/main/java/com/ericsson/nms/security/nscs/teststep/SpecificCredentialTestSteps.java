/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.EXPECTED_MESSAGE;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;

import org.assertj.core.api.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.assertions.TafAsserts;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.nms.security.nscs.data.GetCredentialsValue;
import com.ericsson.oss.testware.enm.cli.EnmCliOperatorImpl;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;
import com.ericsson.oss.testware.nodesecurity.operators.factory.CredentialFactory;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.FdnNormalizer;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.UnsupporteNodeTypeException;
import com.ericsson.oss.testware.security.authentication.tool.TafToolProvider;
import com.google.inject.Provider;

/**
 * Test steps for specific credential commands.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidCatchingGenericException"})
public class SpecificCredentialTestSteps {

    public static final String CRED_CREATE_WITH_PARAMETER = "credentialsCreateWithParam";
    public static final String CRED_UPDATE_WITH_PARAMETER = "credentialsUpdateWithParam";
    public static final String GET_CREDENTIALS = "getCredentials";
    public static final String GET_CREDENTIALS_WITH_FILE_NAME = "getCredentialsWithFileName";
    public static final String GET_NEGATIVE_CREDENTIALS = "getNegativeCredentials";
    public static final String DELETE_SECURITY_INFO_WITH_CHECK = "deleteSecurityInfoWithCheck";

    public static final String CHECK_RESPONSE = "checkResponseDto";
    public static final String ZERO_INSTANCES = "0 instance(s)";
    private static final Logger LOGGER = LoggerFactory.getLogger(SpecificCredentialTestSteps.class);
    private static final int CRED_DELETE_ITERATION = 2;
    private static final int CRED_DELETE_DELAY = 1000;
    private static final int CRED_CHECK_ITERATION = 3;
    private static final int CRED_CHECK_DELAY = 5000;
    @Inject
    private Provider<EnmCliOperatorImpl> cmCliOperatorImpl;

    @Inject
    private CredentialTestSteps credentialTestSteps;

    @Inject
    private TafToolProvider tafToolProvider;

    @Inject
    private RestImpl restImpl;

    @Inject
    private CredentialFactory credentialFactory;

    @TestStep(id = CRED_CREATE_WITH_PARAMETER)
    public void credentialsCreate(@Input(ADDED_NODES) final DataRecord value, @Input(CHECK_RESPONSE) final boolean toCheck)
    throws UnsupporteNodeTypeException {
        final EnmCliResponse responseDto = credentialTestSteps.commandCredentialsCreate(value);
        SecurityUtil.checkResponseDto(responseDto, takeExpectedMessage(value, toCheck));
    }

    @TestStep(id = CRED_UPDATE_WITH_PARAMETER)
    public void credentialsUpdate(@Input(ADDED_NODES) final DataRecord value, @Input(CHECK_RESPONSE) final boolean toCheck)
    throws UnsupporteNodeTypeException {
        final EnmCliResponse responseDto = credentialTestSteps.commandCredentialsUpdate(value);
        SecurityUtil.checkResponseDto(responseDto, takeExpectedMessage(value, toCheck));
    }

    private String takeExpectedMessage(final DataRecord value, final boolean toCheck) {
        return toCheck ? (String) value.getFieldValue(EXPECTED_MESSAGE) : null;
    }

    //TODO (ekeimoo): use flows to compose steps OR! move step in the credential test steps class, instead extending steps
    //TODO (ecappie): code by DespicableUs team
    @TestStep(id = GET_CREDENTIALS)
    public void getCredentials(@Input(ADDED_NODES) final GetCredentialsValue value) {
        final String command = value.getCommand() + value.getNetworkElementId();
        final String expectedMsg = value.getExpectedMsg();
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommand(command, tafToolProvider.getHttpTool());
        LOGGER.info("Response DTO : [ " + responseDto + " ]");
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
        final String expectedResponse1 = value.getExpectedResponse1();
        final String expectedResponse2 = value.getExpectedResponse2();
        final List<String> expectedResponse = new ArrayList<String>();
        expectedResponse.add(expectedMsg);
        expectedResponse.add(expectedResponse1);
        expectedResponse.add(expectedResponse2);
        SecurityUtil.checkResponseDtoMultipleMessage(responseDto, expectedResponse);
    }

    //TODO (ekeimoo): use flows to compose steps OR! move step in the credential test steps class, instead extending steps
    //TODO (ecappie): code by DespicableUs team
    @TestStep(id = GET_CREDENTIALS_WITH_FILE_NAME)
    public void getCredentialsWithFile(@Input(ADDED_NODES) final GetCredentialsValue value) {
        final String command = value.getCommand();
        final String expectedMsg = value.getExpectedMsg();
        final String nodeName = value.getNetworkElementId();
        final String filename = value.getFileName();
        final byte[] fileContents = SecurityUtil.createByteArray(nodeName);
        final File file = new File(filename);
        try {
            final FileOutputStream fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(fileContents);
            fileOutputStream.close();
        } catch (final Exception e) {
            TafAsserts.fail("problem handling file operations");
        }
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommandWithFile(command, file, tafToolProvider.getHttpTool());
        TafAsserts.assertTrue(file.delete());
        LOGGER.info("Response DTO : [ " + responseDto + " ]");
        LOGGER.info("Expecting message : [ " + expectedMsg + " ]");
        SecurityUtil.checkResponseDto(responseDto, expectedMsg);
    }

    @TestStep(id = GET_NEGATIVE_CREDENTIALS)
    public void getNegativeCredentials(@Input(ADDED_NODES) final GetCredentialsValue value) {
        final String command = value.getCommand();
        final String expectedMsg = value.getExpectedMsg();
        final String suggestedSolution = value.getSuggestedSolution();
        LOGGER.info("Sending command : [ " + command + " ]");
        final EnmCliOperatorImpl clicommand = cmCliOperatorImpl.get();
        final EnmCliResponse responseDto = clicommand.executeCliCommand(command, tafToolProvider.getHttpTool());
        final List<String> expectedResponse = new ArrayList<String>();
        expectedResponse.add(expectedMsg);
        expectedResponse.add(suggestedSolution);
        LOGGER.info("Response DTO : [ " + responseDto + " ]");
        SecurityUtil.checkResponseDtoMultipleMessage(responseDto, expectedResponse);
    }

    /**
     * @param value
     */
    @TestStep(id = DELETE_SECURITY_INFO_WITH_CHECK)
    public void deleteSecurityInfoWithCheck(@Input(ADDED_NODES) final DataRecord value) {
        SecurityUtil.checkDataSource(value, ADDED_NODES);
        deleteSecurityInfoWithCheckAndRetry(value);
    }

    private void deleteSecurityInfoWithCheckAndRetry(final DataRecord value) {

        LOGGER.trace("Entering deleteSecurityInfoWithCheckAndRetry");

        EnmCliResponse responseDelete, responseGet;
        int iterationDelete = 0;
        int iterationGet;
        Boolean commandDeleteSuccessful;
        String responseDeleteStatus;
        int responseDeleteErrorCode;
        String responseDeleteErrorMessage;
        String responseDeleteSuggestedSolution;
        String responseGetStatus = "";

        do {
            iterationDelete++;
            LOGGER.info("Executing iterationDelete # [{}]", iterationDelete);

            iterationGet = 0;

            SecurityUtil.delay(CRED_DELETE_DELAY);

            responseDelete = restImpl.sendCommand(
                    credentialFactory.deleteNetworkSecurityNode(FdnNormalizer.normalizeNodeName((String) value.getFieldValue("networkElementId"))));
            commandDeleteSuccessful = responseDelete.isCommandSuccessful();
            responseDeleteStatus = responseDelete.getSummaryDto().getStatusMessage();
            responseDeleteErrorCode = responseDelete.getSummaryDto().getErrorCode();
            responseDeleteErrorMessage = responseDelete.getSummaryDto().getErrorMessage();
            responseDeleteSuggestedSolution = responseDelete.getSummaryDto().getSuggestedSolution();

            if (!commandDeleteSuccessful) {
                break;
            }

            do {
                iterationGet++;
                LOGGER.info("Executing iterationGet # [{}]", iterationGet);
                SecurityUtil.delay(CRED_CHECK_DELAY);
                responseGet = restImpl.sendCommand(credentialFactory.getNetworkSecurityNodeTable(FdnNormalizer.normalizeNodeName((String) value
                        .getFieldValue("networkElementId"))));
                responseGetStatus = responseGet.getSummaryDto().getStatusMessage();
            } while (iterationGet < CRED_CHECK_ITERATION && !ZERO_INSTANCES.equals(responseGetStatus));

        } while (iterationDelete < CRED_DELETE_ITERATION && !ZERO_INSTANCES.equals(responseGetStatus));

        final String assertionMessage;
        if (!commandDeleteSuccessful) {
            assertionMessage = "cmedit delete command not successful";
            LOGGER.info("commandDeleteSuccessful [{}], responseDeleteStatus [{}], responseDeleteErrorCode [{}], responseDeleteErrorMessage [{}], "
                            + "responseDeleteSuggestedSolution [{}]", commandDeleteSuccessful, responseDeleteStatus, responseDeleteErrorCode,
                    responseDeleteErrorMessage, responseDeleteSuggestedSolution);
            Assertions.fail(assertionMessage);
        } else {
            assertionMessage = "cmedit delete command successful, but credentials not successfully deleted";
            Assertions.assertThat(ZERO_INSTANCES.equals(responseGetStatus)).as("\n\n" + assertionMessage + " - Check cmedit delete command...\n")
                    .isTrue();

        }

    }

}
