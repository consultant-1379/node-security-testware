/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.GdprAnonymizedEventFlows;
import com.google.common.collect.Iterables;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class GdprAnonymizedEventTestScenario extends ScenarioUtility {

    private static final String TEST_ID = "MR41595_Q2_Functional_ENM_Privacy_and_GDPR_Compliance";

    @Inject
    UtilityFlows utilityFlows;

    @Inject
    GdprAnonymizedEventFlows gdprAnonymizedEventFlows;


    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestId(id = TEST_ID, title = "GDPR Anonymized Event - Verify Privacy traces on System Recording")
    public void gdprAnonymizedEvents() {
        vUser = Iterables.size(context.dataSource(ADDED_NODES));
        final TestScenario verifyPrivacyTrace = scenario("GDPR Anonymized Event - Verify Privacy traces on System Recording")
                .addFlow(utilityFlows.login(PredicateUtil.nsuPrivacyAdm(), vUser))
                .addFlow(gdprAnonymizedEventFlows.verifyPrivacyTraceOnElasticSearch((SetupAndTeardownScenarioGdprAnonymizedEvent.GDPR_ANONYMIZED_EVENT_DATA_SOURCE))
                        .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))
                .addFlow(utilityFlows.logout(PredicateUtil.nsuPrivacyAdm(), vUser)).build();
        startScenario(verifyPrivacyTrace);

    }
}
