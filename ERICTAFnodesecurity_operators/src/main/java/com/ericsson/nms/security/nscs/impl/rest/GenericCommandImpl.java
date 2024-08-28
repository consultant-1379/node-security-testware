package com.ericsson.nms.security.nscs.impl.rest;

import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.NETWORK_ELEMENT_ID;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.annotations.Operator;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;

/**
 * Generic commands.
 */

@Operator
public class GenericCommandImpl {

    @Inject
    private RestImpl restImpl;

    public EnmCliResponse enableFmSupervision(final DataRecord value) {
        final String command = "alarm enable " + value.getFieldValue(NETWORK_ELEMENT_ID);
        return restImpl.sendCommand(command);
    }

    public EnmCliResponse genericCmeditSet(final String command) {
        return restImpl.sendCommand("cmedit set " + command);
    }
}
