package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NETWORK_ELEMENT_ID;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NODE_INDEX;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;
import javax.inject.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.nms.security.nscs.impl.rest.GenericCommandImpl;
import com.ericsson.oss.testware.enmbase.data.NetworkNode;
import com.ericsson.oss.testware.nodeintegration.exceptions.NodeIntegrationOperatorException;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class GenericTestSteps {

    public static final String CHECK_SYNC = "checkSync";
    public static final String ENABLE_ALARM_SUPERVISION = "enableAlarmSupervision";
    public static final String NON_EXISTENT_NODE = "nonexistentnode";

    private static final Logger log = LoggerFactory.getLogger(GenericTestSteps.class);

    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;

    @Inject
    private Provider<GenericCommandImpl> genericCommandProvider;

    @TestStep(id = CHECK_SYNC)
    public void checkSync(@Input(ADDED_NODES) final NetworkNode value) throws NodeIntegrationOperatorException {
        if (!NON_EXISTENT_NODE.equals(value.getFieldValue(NODE_INDEX))) {
            log.info("checking sync ..... [{}] ", (String)value.getFieldValue(NETWORK_ELEMENT_ID));
            nodeIntegrationTestSteps.confirmNodeSynced(value);
        } else {
            log.info("checking sync skipped .... [{}]", (String)value.getFieldValue(NETWORK_ELEMENT_ID));
        }
    }

    @TestStep(id = ENABLE_ALARM_SUPERVISION)
    public void enableAlarmSupervision(@Input(ADDED_NODES) final DataRecord value) {
        log.info("enabling alarm supervision ..... [{}] ", (String)value.getFieldValue(NETWORK_ELEMENT_ID));
        final GenericCommandImpl genericCommand = genericCommandProvider.get();
        SecurityUtil.checkResponseDto(genericCommand.enableFmSupervision(value), null);
    }
}
