/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.cifwk.taf.assertions.TafAsserts.assertThat;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.EXPECTED_MESSAGE;

import java.util.List;
import javax.inject.Inject;

import org.hamcrest.core.Is;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.assertions.TafAsserts;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.nms.security.nscs.utils.GenericSecadmUtils;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.operators.RestImpl;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.UnsupporteNodeTypeException;

/**
 * A TAF test-step class to perform Job Id test for Certificate Issue command
 *
 * @author The16thFloor
 * @version 1.15, 22 September 2016
 */
@SuppressWarnings({"PMD.AvoidCatchingGenericException"})
public class JobIdSpecificIssueTestSteps {

    // TestStep list for Job Id
    public static final String CERTIFICATE_ISSUE_WITH_JOB_ID = "certificateIssueWithJobId";
    private static final Logger LOGGER = LoggerFactory.getLogger(JobIdSpecificIssueTestSteps.class);

    @Inject
    private RestImpl restImpl;

    @Inject
    private GenericSecadmUtils secadmUtils;

    @Inject
    private CertificateIssueTestSteps certificateIssueTestStep;

    /**
     * This test step performs Certificate Issue with creation of a Job Id. <br/>
     * <br/>
     * It performs the following steps:
     * <ul>
     * <li>Checks if the node is still synchronized</li>
     * <li>Starts certificate issue command</li>
     * <li>Checks if the command has started successfully</li>
     * <li>If success, the response msg is elaborated in order to gain the 'get jobid' command</li>
     * <li>Launch the 'get jobid' command</li>
     * <li>Verify that jobid is created</li>
     * <li>Verify that jobid status is according with workflow's status</li>
     * <li>Launch the 'get jobid' command other 2 times and perform the same checks.</li>
     * </ul>
     *
     * @param value
     *         contains the values of csv datasource
     *
     * @see DataRecord
     */
    @TestStep(id = CERTIFICATE_ISSUE_WITH_JOB_ID)
    public void issueCreateJobIdVerify(@Input(ADDED_NODES) final DataRecord value) throws UnsupporteNodeTypeException {
        LOGGER.info("issueCreateJobIdVerify -> START");
        final EnmCliResponse issueDto;
        try {
            issueDto = certificateIssueTestStep.certIssueCommand(value);
            SecurityUtil.checkResponseDto(issueDto, (String) value.getFieldValue(EXPECTED_MESSAGE));
            final List<String> responseMsg = SecurityUtil.listOfLines(issueDto);
            String getJobCmd = null;
            for (final String msg : responseMsg) {
                if (msg.contains("secadm job get")) {
                    getJobCmd = GenericSecadmUtils.extractCmd(msg);
                    break;
                }
            }
            LOGGER.info("Job Get Command ->" + getJobCmd);
            for (int i = 1; i <= 10; i++) {
                LOGGER.info("COMMAND 'secadm job get...' ---- Attempt: {}", i);
                LOGGER.info(" - - - - - Launching getJobCmd = {}", getJobCmd);
                final String jobId = GenericSecadmUtils.extractUuId(getJobCmd);
                LOGGER.info("Job ID = {}", jobId);
                final EnmCliResponse getJobDto = restImpl.sendCommand(getJobCmd);
                SecurityUtil.checkResponseDto(getJobDto, (String) value.getFieldValue(EXPECTED_MESSAGE));
                final boolean checkOk = secadmUtils.checkJobGetCmdResponse(jobId, getJobDto);
                if (checkOk) {
                    assertThat(CERTIFICATE_ISSUE_WITH_JOB_ID, checkOk, Is.is(true));
                    break;
                } else {
                    Thread.sleep(12000);
                }
            }
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
            TafAsserts.fail("Error creating xml for certificate issue");
        }
    }
}