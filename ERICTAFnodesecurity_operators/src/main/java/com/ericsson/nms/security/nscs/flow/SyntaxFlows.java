/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CREDENTIAL_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_CREDENTIAL_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_SSH_KEY_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_SSH_KEY_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_TRUST_REMOVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SYNTAX_ERROR_TRUST_REMOVE_TESTS_CSV;

import java.util.List;
import java.util.Map;

import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.nms.security.nscs.teststep.SyntaxTestSteps;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.google.common.collect.Lists;
import com.google.inject.Inject;

/**
 * Flows for syntax error command.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.DoNotUseThreads"})
public class SyntaxFlows extends BaseFlow {

    @Inject
    SyntaxTestSteps syntaxTestSteps;

    /**
     * Run command and check syntax error.
     *
     * @return TestStepFlow
     */
    public TestStepFlow syntaxSendFlow() {
        return flow("Syntax Send Flows").beforeFlow(addSyntaxDataSourceFromCsv()).afterFlow(resetDataSource(SyntaxTestSteps.SYNTAX_DATASOURCE))
                .addTestStep(annotatedMethod(syntaxTestSteps, SyntaxTestSteps.SYNTAX_SEND))
                .withDataSources(dataSource(SyntaxTestSteps.SYNTAX_DATASOURCE)).build();
    }

    private Runnable addSyntaxDataSourceFromCsv() {
        return new Runnable() {
            @Override
            public void run() {
                final String sourcePath = Utils.getSourcePath();
                context.addDataSource(SyntaxTestSteps.SYNTAX_DATASOURCE, TestDataSourceFactory.createDataSource(fillSyntaxDataSource(sourcePath)));
            }
        };
    }

    private List<Map<String, Object>> fillSyntaxDataSource(final String sourcePath) {
        context.addDataSource(SYNTAX_ERROR_CREDENTIAL_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_CREDENTIAL_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_SSH_KEY_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_SSH_KEY_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_TRUST_REMOVE_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_TRUST_REMOVE_TESTS_CSV));
        context.addDataSource(SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS, fromCsv(sourcePath + SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS_CSV));
        final List<Map<String, Object>> credSyntax = Utils
                .copyDataSource(context.dataSource(SYNTAX_ERROR_CREDENTIAL_TESTS), SYNTAX_ERROR_CREDENTIAL_TESTS);
        final List<Map<String, Object>> credSnmpSyntax = Utils.copyDataSource(context.dataSource(SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS), SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS);
        final List<Map<String, Object>> kgSyntax = Utils.copyDataSource(context.dataSource(SYNTAX_ERROR_SSH_KEY_TESTS), SYNTAX_ERROR_SSH_KEY_TESTS);
        final List<Map<String, Object>> issueSyntax = Utils
                .copyDataSource(context.dataSource(SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS), SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS);
        final List<Map<String, Object>> reissueyntax = Utils
                .copyDataSource(context.dataSource(SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS), SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS);
        final List<Map<String, Object>> trustDistrSyntax = Utils
                .copyDataSource(context.dataSource(SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS), SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS);
        final List<Map<String, Object>> trustRemoveSyntax = Utils
                .copyDataSource(context.dataSource(SYNTAX_ERROR_TRUST_REMOVE_TESTS), SYNTAX_ERROR_TRUST_REMOVE_TESTS);
        final List<Map<String, Object>> syntaxDataSource = Lists.newArrayList();
        syntaxDataSource.addAll(credSyntax);
        syntaxDataSource.addAll(credSnmpSyntax);
        syntaxDataSource.addAll(kgSyntax);
        syntaxDataSource.addAll(issueSyntax);
        syntaxDataSource.addAll(reissueyntax);
        syntaxDataSource.addAll(trustDistrSyntax);
        syntaxDataSource.addAll(trustRemoveSyntax);
        return syntaxDataSource;
    }
}
