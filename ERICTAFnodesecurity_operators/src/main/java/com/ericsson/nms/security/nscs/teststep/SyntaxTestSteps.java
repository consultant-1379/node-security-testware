/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_ROLE_DEFINITION_TESTS;

import javax.inject.Inject;
import javax.inject.Provider;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.nms.security.nscs.data.RbacErrorsValue;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;

/**
 * Test steps for syntax error commands.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SyntaxTestSteps {

    public static final String SYNTAX_SEND = "syntaxSendCommand";
    public static final String SYNTAX_RBAC_ERROR = "syntaxRbacError";
    public static final String SYNTAX_DATASOURCE = "syntaxDataSource";
    public static final String SYNTAX_ERROR_MESSAGE = "Error 10001 : Command syntax error";

    @Inject
    Provider<RestImpl> provider;

    /**
     * Run syntax error command and check error message.
     *
     * @param value
     *         SyntaxValue
     */
    @TestStep(id = SYNTAX_SEND)
    public void syntaxCommand(@Input(SYNTAX_DATASOURCE) final DataRecord value) {
        final RestImpl restImpl = provider.get();
        SecurityUtil.checkResponseDto(restImpl.sendCommand((String) value.getFieldValue("command")), SYNTAX_ERROR_MESSAGE);
    }

    /**
     * Run syntax error command for role base and check error message.
     *
     * @param value
     *         RbacErrorsValue
     */
    @TestStep(id = SYNTAX_RBAC_ERROR)
    public void syntaxRbacCommand(@Input(SYNTAX_ERROR_ROLE_DEFINITION_TESTS) final RbacErrorsValue value) {
        final RestImpl restImpl = provider.get();
        SecurityUtil.checkResponseDto(restImpl.sendCommand(value.getCommand()), value.getExpected());
    }
}
