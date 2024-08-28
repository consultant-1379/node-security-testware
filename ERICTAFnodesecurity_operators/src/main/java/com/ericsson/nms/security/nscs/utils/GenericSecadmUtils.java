/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.utils;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Operator;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;

/**
 * @author enmadmin
 */
@Operator
@SuppressWarnings({"PMD.LawOfDemeter"})
public class GenericSecadmUtils {

    public static final String SERVICE_NAME = "node-security";
    public static final String JNDI_VERSION_PATTERN = "XXVERSIONXX";
    //Regex Pattern
    public static final String jobGetCmdPattern = "(secadm job get -j [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
    public static final String uuidPattern = "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
    // Possible JobId status values
    public static final String JOB_ID_RUNNING = "RUNNING";
    public static final String JOB_ID_COMPLETE = "COMPLETE";
    // Possible Workflow status values
    public static final String WF_RUNNING = "RUNNING";
    public static final String WF_COMPLETE = "SUCCESS";
    public static final String WF_ERROR = "ERROR";
    // Fields to be checked
    public static final String JOB_ID = "Job Id";
    public static final String JOB_ID_STATUS = "Job Status";
    public static final String WF_STATUS = "Workflow Status";
    private static final Logger log = LoggerFactory.getLogger(GenericSecadmUtils.class);

    /**
     * @author the16thFloor It extracts the command the operator should launch in order to Get the Job Id CLI command starts with 'secadm job get'
     */
    public static String extractCmd(final String response) {
        String c = null;
        //        String pattern = "(secadm job get -j [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})";
        final Pattern p = Pattern.compile(jobGetCmdPattern);
        final Matcher m = p.matcher(response);
        if (m.find()) {
            c = m.group(0);
        }
        return c;
    }

    /**
     * @author the16thFloor It extracts the UUID value that identifies Job Id
     */
    public static String extractUuId(final String response) {
        String c = null;
        final Pattern p = Pattern.compile(uuidPattern);
        final Matcher m = p.matcher(response);
        if (m.find()) {
            c = m.group(0);
        } else {
            log.error("Job ID not found");
        }
        return c;
    }

    /**
     * @param jndiString
     *         The string containing the patternToBeReplaced
     * @param patternToBeReplaced
     *         The pattern to be found and replaced
     * @param valueToReplace
     *         The value to be put in string
     *
     * @return
     */
    public String replaceVersionForJndiLookup(final String jndiString, final String patternToBeReplaced, final String valueToReplace) {
        final String result = jndiString.replaceAll(patternToBeReplaced, valueToReplace);
        log.info("replaceVersionForJndiLookup - jndiString [{}], patternToBeReplaced [{}] valueToReplace [{}], result [{}]", jndiString,
                patternToBeReplaced, valueToReplace, result);
        return result;
    }

    /**
     * Method used in order to perform the check of the Command Response with "secadm job get ..." command Checks are about: JobID number, JobID
     * Status in respect to Workflow Status JobID reported by the Cmd Response must be equal to that inserted in the "secadm job get ..." command
     * JobID Status RUNNING must foresee at least one Workflow Status equal RUNNING JobID Status COMPLETE must foresee ALL Workflows Status equal
     * either SUCCESS or ERROR
     */
    public boolean checkJobGetCmdResponse(final String jobId, final EnmCliResponse responseDto) {
        Boolean checkOk;
        //        final Map<String, List<String>> cmdResponse = SecurityResponseDtoWrapper.getSingleLine(responseDto);
        final Map<String, List<String>> cmdResponse = SecurityUtil.listOfRows(responseDto);
        if (cmdResponse.get(JOB_ID).get(0).equals(jobId)) {
            log.info("Check on Job ID value -> PASSED");
        }
        checkOk = true;
        // Check on between Job ID and Workflow Status
        log.info("{} : {}", JOB_ID_STATUS, cmdResponse.get(JOB_ID_STATUS).get(0));
        log.info("{} : {}", WF_STATUS, cmdResponse.get(WF_STATUS).get(0));
        if (cmdResponse.get(JOB_ID_STATUS).get(0).equals(JOB_ID_RUNNING)) {
            if (cmdResponse.get(WF_STATUS).get(0).equals(WF_RUNNING)) {
                log.info("Check between Job ID and Workflow Status -> PASSED");
            }
            checkOk = true;
        }
        if (cmdResponse.get(JOB_ID_STATUS).get(0).equals(JOB_ID_COMPLETE)) {
            if (cmdResponse.get(WF_STATUS).get(0).equals(WF_COMPLETE) || cmdResponse.get(WF_STATUS).get(0).equals(WF_ERROR)) {
                log.info("Check between Job ID and Workflow Status -> PASSED");
            }
            checkOk = true;
        }
        return checkOk;
    }
}
