package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.afterStep;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.beforeStep;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants;
import com.ericsson.nms.security.nscs.flow.PkiCommandFlow;
import com.ericsson.nms.security.nscs.flow.TrustDistributeFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;

//import com.ericsson.nms.security.nscs.flow.TrustRemoveFlow; 

/**
 * A TAF scenario class to perform Manage Trust Certificate on pRBS node Positive tests
 *
 * @author Maria Antonia Vaccarello
 * @version , 19 September 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CertificateTrustManagementECIMPositiveScenario extends TafTestBase {

    private static final Logger log = LoggerFactory.getLogger(CertificateTrustManagementECIMPositiveScenario.class);
    private static final String TITLE = "[FCAPS pRBP] customization of Trust Distribution (IPSEC) for pRBS";

    // @Inject
    //private TrustRemoveFlow trustRemoveFlow;
    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;
    @Inject
    TestContext context;
    @Inject
    private TrustDistributeFlow trustDistributeFlow;
    @Inject
    private PkiCommandFlow pkiFlow;
    @Inject
    private BaseScenario baseScenario;

    @BeforeClass
    public void setupDataSourceForComEcimScenario() {
        log.info("Datasource for ComEcim Integration Scenario" + CsvDataSourceConstants.TRUST_PROFILE_CREATION_POSITIVE_TESTS);
        context.addDataSource(CsvDataSourceConstants.TRUST_PROFILE_CREATION_POSITIVE_TESTS,
                fromCsv(CsvDataSourceConstants.TRUST_PROFILE_CREATION_POSITIVE_TESTS_CSV));
        context.addDataSource(CsvDataSourceConstants.TRUST_PROFILE_REMOVE_POSITIVE_TESTS,
                fromCsv(CsvDataSourceConstants.TRUST_PROFILE_REMOVE_POSITIVE_TESTS_CSV));
        context.addDataSource(CsvDataSourceConstants.ENTITY_PROFILE_CREATION_POSITIVE_TESTS,
                fromCsv(CsvDataSourceConstants.ENTITY_PROFILE_CREATION_POSITIVE_TESTS_CSV));
        context.addDataSource(CsvDataSourceConstants.ENTITY_PROFILE_REMOVE_POSITIVE_TESTS,
                fromCsv(CsvDataSourceConstants.ENTITY_PROFILE_REMOVE_POSITIVE_TESTS_CSV));
        context.addDataSource(CsvDataSourceConstants.ENTITY_UPDATE_POSITIVE_TESTS, fromCsv(CsvDataSourceConstants.ENTITY_UPDATE_POSITIVE_TESTS_CSV));

    }

    /**
     * Trust Remove certificate on pRBS node scenario
     */

    @Test(enabled = true, priority = 1, groups = { "Acceptance" })
    @TestId(id = "TORF-142997", title = TITLE)
    public void integrationTrustDistributeScenario() {

        final TestScenario scenario = scenario(TITLE).addFlow(loginlogoutFlow.loginDefaultUser()).addFlow(pkiFlow.trustProfileCreate())
                .addFlow(pkiFlow.entityProfileCreate()).addFlow(pkiFlow.retrievEeId()).addFlow(pkiFlow.updateEe(beforeStep))
                .addFlow(trustDistributeFlow.trustDistributeCertType())
                // to be verified
                //.addFlow(trustDistributeFlow.trustGet()) // this step has to be introduced after testware refactoring
                //.addFlow(trustRemoveFlow.trustRemoveByCAPositive())
                //.addFlow(trustDistributeFlow.trustGet()) // this step has to be introduced after testware refactoring
                .addFlow(pkiFlow.retrievEeId()).addFlow(pkiFlow.updateEe(afterStep)).addFlow(pkiFlow.entityProfileRemove())
                .addFlow(pkiFlow.trustProfileRemove()).addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);

    }

}
