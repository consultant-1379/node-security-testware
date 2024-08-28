/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.impl.rest;

import com.ericsson.cifwk.taf.annotations.Operator;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;

/**
 * Generic Pki Command.
 */
@Operator
public class PkiCommandsImpl extends RestImpl {

    public EnmCliResponse createSHA1() {
        final String commandString = "pkiadm configmgmt algo --enable --name SHA1";
        return sendSecurityCommand(commandString, null, null);
    }

    public EnmCliResponse pkiReadStatusCertificate(final String entityName, final String status) {
        final String commandString = String.format("pkiadm certmgmt EECert --list --entityname %s --status %s", entityName, status);
        return sendSecurityCommand(commandString, null, null);
    }

    public EnmCliResponse profileMngCreate(final String fileName, final byte[] fileContents) {
        final String commandString = "pkiadm pfm -c -xf file:" + fileName;
        return sendSecurityCommand(commandString, fileName, fileContents);
    }

    public EnmCliResponse entityMngUpdate(final String fileName, final byte[] fileContents) {
        final String commandString = "pkiadm etm -u -xf file:" + fileName;
        return sendSecurityCommand(commandString, fileName, fileContents);
    }
}
