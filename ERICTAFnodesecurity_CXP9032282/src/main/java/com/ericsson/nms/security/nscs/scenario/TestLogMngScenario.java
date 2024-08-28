/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.isCppNode;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.util.ArrayList;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.arnlrfa250scenario.LogScenarioUtility;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

/**
 * TestLogMngScenario is a class for testing log mng.
 */
public class TestLogMngScenario extends LogScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestLogMngScenario.class);

    @BeforeSuite(enabled = true, alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    public void beforeClass() {
        final TestDataSource<DataRecord> netsimDatasource = fromTafDataProvider(NODES_TO_ADD);
        debugScope(LOGGER, netsimDatasource);
        final TestDataSource<DataRecord> nodeListFilteredByUser = TafDataSources.filter(netsimDatasource, isCppNode);
        debugScope(LOGGER, nodeListFilteredByUser);
        context.addDataSource(ADDED_NODES, nodeListFilteredByUser);
    }

    @Test(enabled = true, groups = { "Functional", "NSS", "RFA250", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void sl2EnableScenario() {
        enableLogMng(LOG_ENABLE_SCRIPT_FILENAME, "SL2ON");
        disableLogMng(LOG_DISABLE_SCRIPT_FILENAME, "SL2ON");
    }

    @Test(enabled = true, groups = { "Functional", "NSS", "RFA250", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void sl2DisableScenario() {
        enableLogMng(LOG_ENABLE_SCRIPT_FILENAME, "SL2OFF");
        disableLogMng(LOG_DISABLE_SCRIPT_FILENAME, "SL2OFF");
    }

    @Test(enabled = true, groups = { "Functional", "NSS", "RFA250", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void issuereissueScenario() {
        enableLogMng(LOG_ENABLE_SCRIPT_FILENAME, "ISSUEREISSUE");
        disableLogMng(LOG_DISABLE_SCRIPT_FILENAME, "ISSUEREISSUE");
    }

    @Test(enabled = true, groups = { "Functional", "NSS", "RFA250", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustScenario() {
        enableLogMng(LOG_ENABLE_SCRIPT_FILENAME, "TRUST");
        disableLogMng(LOG_DISABLE_SCRIPT_FILENAME, "TRUST");
    }

    @Test(enabled = true, groups = { "Functional", "NSS", "RFA250", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void crlcheckScenario() {
        enableLogMng(LOG_ENABLE_SCRIPT_FILENAME, "CRLCHECK");
        disableLogMng(LOG_DISABLE_SCRIPT_FILENAME, "CRLCHECK");
    }

    public static void debugScope(final Logger logger, final TestDataSource<? extends DataRecord> values) {
        final Iterable iterableValues = Iterables.unmodifiableIterable(values);
        final Iterator iteratorValues = iterableValues.iterator();
        final ArrayList myList = Lists.newArrayList(iteratorValues);
        for (int i = 0; i < myList.size(); ++i) {
            final DataRecord next = (DataRecord) myList.get(i);
            final String value = next.toString();
            logger.debug("Datasource row --- " + value);
        }
        if (myList.size() == 0) {
            logger.debug("TestDataSource EMPTY --- " + values.toString());
        }
    }
}
