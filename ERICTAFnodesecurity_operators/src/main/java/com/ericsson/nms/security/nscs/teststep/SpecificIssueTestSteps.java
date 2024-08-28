/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.teststep;

import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SUITE_PROFILE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.CERT_TYPE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.ENROLLMENT_MODE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.ENTITY_PROFILE_NAME;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.JOB_ID_ELEMENT_VALUE_LIST;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.KEY_SIZE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.NETWORK_ELEMENT_ID;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.NODE_TYPE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.SUBJECT_ALTNAME;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.SUBJECT_ALTNAME_TYPE;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_AFTER;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_BEFORE;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.annotations.Input;
import com.ericsson.cifwk.taf.annotations.TestStep;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordBuilder;
import com.ericsson.nms.security.nscs.flow.BaseFlow;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.enm.cli.EnmCliResponse;
import com.ericsson.oss.testware.nodesecurity.operators.CertificateIssueImpl;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateReissueTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.CertificateIssueUtils;
import com.ericsson.oss.testware.nodesecurity.utils.JobIdUtils;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.UnsupporteNodeTypeException;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.XmlComposerException;

/**
 * Test steps for specific certificate issue command.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class SpecificIssueTestSteps {

    public static final String SPECIFIC_CERTIFICATE_VERIFY = "specificCertificateVerify";
    public static final String SPECIFIC_CERTIFICATE_ISSUE_MIX = "specificCertificateIssueMix";
    public static final String SPECIFIC_CERTIFICATE_REISSUE_MIX = "specificCertificateReissueMix";
    public static final String SPECIFIC_CERTIFICATE_GET_MIX = "specificCertificateGetMix";

    public static final String INPUT_CSV = "inputCsvValue";
    public static final String CERT_TYPE_VALUE = "certTypeValue";
    public static final String CERT_GET_RESULT = "certGetResult";
    public static final String INPUT_DATA_SOURCE_NAME = "CERT_ISSUE_MIX";

    private static final Logger LOGGER = LoggerFactory.getLogger(SpecificIssueTestSteps.class);

    @Inject
    private CertificateReissueTestSteps certificateReissueTestSteps;

    @Inject
    private CertificateIssueUtils certificateIssueUtils;

    @Inject
    private BaseFlow baseFlow;

    @Inject
    private Provider<CertificateIssueImpl> provider;

    /**
     * Perform the check between enroll state before and after issue certificate.
     *
     * @param enrollStateBefore
     *         enroll state before issue certificate
     * @param enrollStateAfter
     *         enroll state after issue certificate
     */
    @TestStep(id = SPECIFIC_CERTIFICATE_VERIFY)
    public void certificateIssueVerify(@Input(ENROLL_STATE_BEFORE) final EnmCliResponse enrollStateBefore,
            @Input(ENROLL_STATE_AFTER) final EnmCliResponse enrollStateAfter) {
        certificateIssueUtils.checkIssueCertificate(JOB_ID_ELEMENT_VALUE_LIST, enrollStateBefore, enrollStateAfter);
    }

    /**
     * For each row of input csv file with the same suiteProfile one xml file will be composed.
     *
     * @param inputCsv
     *         input csv
     * @param certTypeValue
     *         cert type value
     *
     * @return the job id get command
     */
    @TestStep(id = SPECIFIC_CERTIFICATE_ISSUE_MIX)
    public DataRecord specificCertificateIssueMix(@Input(INPUT_CSV) final String inputCsv, @Input(CERT_TYPE_VALUE) final String certTypeValue)
    throws UnsupporteNodeTypeException {
        final List<DataRecord> dataRecords = new ArrayList<>();
        final List<Map<String, Object>> rows = baseFlow.fillListOfRows(inputCsv, INPUT_DATA_SOURCE_NAME, NodeType.ERBS.toString());
        for (final Map<String, Object> row : rows) {
            if (UtilContext.makeUtilContext().readSuiteProfile().equals(row.get(SUITE_PROFILE))) {
                final DataRecordBuilder dataRecordBuilder = new DataRecordBuilder();
                dataRecordBuilder.setField(NETWORK_ELEMENT_ID, row.get(NETWORK_ELEMENT_ID));
                dataRecordBuilder.setField(NODE_TYPE, row.get(NODE_TYPE));
                dataRecordBuilder.setField(CERT_TYPE, certTypeValue);
                dataRecordBuilder.setField(ENROLLMENT_MODE, row.get(ENROLLMENT_MODE));
                dataRecordBuilder.setField(ENTITY_PROFILE_NAME, row.get(ENTITY_PROFILE_NAME));
                dataRecordBuilder.setField(KEY_SIZE, row.get(KEY_SIZE));
                dataRecordBuilder.setField(SUBJECT_ALTNAME, row.get(SUBJECT_ALTNAME));
                dataRecordBuilder.setField(SUBJECT_ALTNAME_TYPE, row.get(SUBJECT_ALTNAME_TYPE));
                dataRecords.add(dataRecordBuilder.build());
            }
        }
        try {
            final CertificateIssueImpl certIssueImpl = provider.get();
            final EnmCliResponse responseDto = certIssueImpl.createIssue(dataRecords);
            SecurityUtil.checkResponseDto(responseDto, null);
            return JobIdUtils.fillJobIdDataRecord(responseDto, JOB_ID_ELEMENT_VALUE_LIST, null);
        } catch (final XmlComposerException ex) {
            LOGGER.error(ex.getMessage(), ex);
        }
        return null;
    }

    @TestStep(id = SPECIFIC_CERTIFICATE_GET_MIX)
    public EnmCliResponse specificCertificateGetMix(@Input(INPUT_CSV) final String inputCsv, @Input(CERT_TYPE_VALUE) final String certTypeValue)
    throws UnsupporteNodeTypeException {
        final DataRecord commandParams = readNodeNames(inputCsv, certTypeValue);
        final EnmCliResponse responseDto = certificateIssueUtils.certIssueGetCommand(commandParams);
        SecurityUtil.checkResponseDto(responseDto, null);
        return responseDto;
    }

    @TestStep(id = SPECIFIC_CERTIFICATE_REISSUE_MIX)
    public DataRecord specificCertificateReissueMix(@Input(INPUT_CSV) final String inputCsv, @Input(CERT_TYPE_VALUE) final String certTypeValue)
    throws UnsupporteNodeTypeException {
        final DataRecord commandParams = readNodeNames(inputCsv, certTypeValue);
        return certificateReissueTestSteps.certificateReissueCertType(commandParams, null);
    }

    private DataRecord readNodeNames(final String inputCsv, final String certTypeValue) {
        final List<Map<String, Object>> rows = baseFlow.fillListOfRows(inputCsv, INPUT_DATA_SOURCE_NAME, NodeType.ERBS.toString());
        String nodeList = "";
        for (final Map<String, Object> row : rows) {
            if (UtilContext.makeUtilContext().readSuiteProfile().equals(row.get(SUITE_PROFILE))) {
                nodeList += row.get(NETWORK_ELEMENT_ID) + ",";
            }
        }
        nodeList = nodeList.substring(0, nodeList.lastIndexOf(","));
        final DataRecordBuilder dataRecord = new DataRecordBuilder();
        dataRecord.setField(NODE_TYPE, NodeType.ERBS.toString());
        dataRecord.setField(CERT_TYPE, certTypeValue);
        dataRecord.setField(NETWORK_ELEMENT_ID, nodeList);
        return dataRecord.build();
    }
}
