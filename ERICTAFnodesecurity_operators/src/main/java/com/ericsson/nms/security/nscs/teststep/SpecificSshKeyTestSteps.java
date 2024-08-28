/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.EXPECTED_MESSAGE;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.steps.SshKeyTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.UnsupporteNodeTypeException;

/**
 * Test steps for Ssh Key commands.
 */
public class SpecificSshKeyTestSteps {

    public static final String SSH_KEY_CREATE_WITH_PARAMETER = "sshKeyCreateNegative";
    public static final String SSH_KEY_UPDATE_WITH_PARAMETER = "sshKeyUpdateNegative";
    public static final String CHECK_RESPONSE = "checkResponseDto";

    @Inject
    SshKeyTestSteps sshKeyTestSteps;

    /**
     * Run Ssh Key create command.
     *
     * @param value
     *         DataRecord
     * @param toCheck
     *         if true check return message.
     */
    @TestStep(id = SSH_KEY_CREATE_WITH_PARAMETER)
    public void sshKeyCreate(@Input(ADDED_NODES) final DataRecord value, @Input(CHECK_RESPONSE) final boolean toCheck)
    throws UnsupporteNodeTypeException {
        final EnmCliResponse responseDto = sshKeyTestSteps.createSshKey(value);
        SecurityUtil.checkResponseDto(responseDto, takeExpectedMessage(value, toCheck));
    }

    /**
     * Run Ssh Key update command.
     *
     * @param value
     *         DataRecord
     * @param toCheck
     *         if true check return message.
     */
    @TestStep(id = SSH_KEY_UPDATE_WITH_PARAMETER)
    public void sshKeyUpdate(@Input(ADDED_NODES) final DataRecord value, @Input(CHECK_RESPONSE) final boolean toCheck)
    throws UnsupporteNodeTypeException {
        final EnmCliResponse responseDto = sshKeyTestSteps.updateSshKey(value);
        SecurityUtil.checkResponseDto(responseDto, takeExpectedMessage(value, toCheck));
    }

    private String takeExpectedMessage(final DataRecord value, final boolean toCheck) {
        return toCheck ? (String) value.getFieldValue(EXPECTED_MESSAGE) : null;
    }
}
