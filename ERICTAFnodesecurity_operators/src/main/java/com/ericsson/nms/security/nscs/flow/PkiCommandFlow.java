/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_PROFILE_CREATION_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_PROFILE_REMOVE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.ENTITY_UPDATE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_PROFILE_CREATION_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_PROFILE_REMOVE_POSITIVE_TESTS;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.teststep.PkiCommandsTestSteps;
import com.google.common.base.Predicate;

/**
 * Flows for pki commands.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class PkiCommandFlow extends BaseFlow {

    @Inject
    private PkiCommandsTestSteps pkiCommandTestSteps;

    /**
     * Run pki command to enable SHA-1.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder enableSha1() {
        return flow("Enable SHA1").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.PKI_ENABLE_SHA1));
    }

    public TestStepFlowBuilder trustProfileCreate() {
        return flow("Trust Profile Creation").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.PROFILEMNG_CREATE))
                .withDataSources(dataSource(TRUST_PROFILE_CREATION_POSITIVE_TESTS));
    }

    public TestStepFlowBuilder trustProfileRemove() {
        return flow("Trust Profile Creation").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.PROFILEMNG_REMOVE))
                .withDataSources(dataSource(TRUST_PROFILE_REMOVE_POSITIVE_TESTS));
    }

    public TestStepFlowBuilder entityProfileCreate() {
        return flow("Entity Profile Creation").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.ENTITYMNG_CREATE))
                .withDataSources(dataSource(ENTITY_PROFILE_CREATION_POSITIVE_TESTS));
    }

    public TestStepFlowBuilder entityProfileRemove() {
        return flow("Entity Profile Remove").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.ENTITYMNG_REMOVE))
                .withDataSources(dataSource(ENTITY_PROFILE_REMOVE_POSITIVE_TESTS));
    }

    public TestStepFlowBuilder updateEe(final Predicate<DataRecord> filter) {
        return flow("End Entity Update").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.ENTITYMNG_UPDATE))
                .withDataSources(dataSource(ENTITY_UPDATE_POSITIVE_TESTS).withFilter(filter));
    }

    public TestStepFlowBuilder retrievEeId() {
        return flow("Get End Entity Id").addTestStep(annotatedMethod(pkiCommandTestSteps, PkiCommandsTestSteps.RETRIEVE_EE_ID));
    }

}
