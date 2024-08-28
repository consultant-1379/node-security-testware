/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.scenario;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.management.TafContext;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.utils.UtilContext;

/**
 * Setup and tear down the nodes.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidCatchingGenericException"})
public class SetUpTearDownScenario extends TafTestBase {

    private static final Logger log = LoggerFactory.getLogger(SetUpTearDownScenario.class);

    @Inject
    private BaseScenario baseScenario;

    /**
     * Setup the nodes.
     *
     * @param dataprovidername
     *         the name of data provider in datadriven.properties
     * @param suiteNscsProfiles
     *         the name of suite profile
     */
    @Parameters({ "dataprovidername", "nscsprofiles" })
    @BeforeSuite(alwaysRun = true, groups = { "RFA250", "NSS", "ARNL" })
    public void onBeforeSuite(final String dataprovidername, final String suiteNscsProfiles) {
        try {
            baseScenario.beforeSuite(dataprovidername, suiteNscsProfiles);
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * Tear down the nodes.
     */
    @AfterSuite(alwaysRun = true, groups = { "RFA250" })
    public void onAfterSuite() {
        log.info("*******  tearDownEnvironment [{}] ********", TafContext.SUITE_NAME);
        if (!SecurityConstants.PROFILE_SETUP.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            baseScenario.createTeardown();
        }
    }
}
