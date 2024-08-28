package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SSL_DEFINITION_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SSL_DEFINITION_DATASOURCE;

import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.NetSimTestStep;
import com.google.common.base.Predicate;

/**
 * Flows for Ssl Definition copy/create/apply/delete.
 */
// TODO remove all class
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.DoNotUseThreads"})
public class SslDefinitionFlow extends BaseFlow {

    private static final Logger log = LoggerFactory.getLogger(SslDefinitionFlow.class);

    @Inject
    NetSimTestStep netsimTestStep;

    /**
     * Copy certificate on the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder copySslDefinition() {
        return flow("Copying Ssl Definition").beforeFlow(addSslDefinitionDataSource()).pause(2, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(netsimTestStep, NetSimTestStep.COPY_SSL_DEFINITION_STEP))
                .withDataSources(dataSource(SSL_DEFINITION_DATASOURCE).withFilter(PredicatesExt.byProfile));
    }

    /**
     * Create Ssl Definition on the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder createSslDefinition() {
        return flow("Creating Ssl Definition").pause(2, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(netsimTestStep, NetSimTestStep.CREATE_SSL_DEFINITION_STEP))
                .withDataSources(dataSource(SSL_DEFINITION_DATASOURCE).withFilter(PredicatesExt.byProfile));
    }

    /**
     * Apply Ssl Definition on the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder applySslDefinition() {
        return flow("Applying Ssl Definition").pause(2, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(netsimTestStep, NetSimTestStep.APPLY_SSL_DEFINITION_STEP))
                .withDataSources(dataSource(SSL_DEFINITION_DATASOURCE).withFilter(PredicatesExt.byProfile));
    }

    /**
     * Delete Ssl Definition from the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder deleteSslDefinition(final Predicate<DataRecord> predicate) {
        return flow("Deleting Ssl Definition").pause(2, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(netsimTestStep, NetSimTestStep.DELETE_SSL_DEFINITION_STEP))
                .withDataSources(dataSource(SSL_DEFINITION_DATASOURCE).withFilter(predicate));
    }

    private Runnable addSslDefinitionDataSource() {
        return new Runnable() {
            @Override
            public void run() {
                context.addDataSource(SSL_DEFINITION_DATASOURCE, fromCsv(SSL_DEFINITION_CSV));
                log.debug("addSslDefinitionDataSource... loading csv [{}]", SSL_DEFINITION_CSV);
                log.debug("addSslDefinitionDataSource... LOADED CSV");
            }
        };
    }
}
