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

package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.util.ArrayList;
import java.util.Iterator;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.UnknownDataSourceTypeException;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

/**
 * ScenarioUtil contains base scenario utilities.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class ScenarioUtil extends TafTestBase {

    public static final String NO_DATA = "No Data in Data Source";
    private static final Logger LOGGER = LoggerFactory.getLogger(ScenarioUtil.class);

    protected int numberOfNodes;

    @Inject
    protected TestContext context;

    /**
     * Only for debug scope: this function prints each single row of a datasource.
     *
     * @param logger
     *         logger
     * @param name
     *         key name of the datasource
     */
    public static void debugScope(final Logger logger, final String name) {
        logger.debug("Datasource {} contents start", name);
        final TestContext context = TafTestContext.getContext();
        if (context.doesDataSourceExist(name)) {
            final TestDataSource<? extends DataRecord> values = TafDataSources.copy(context.dataSource(name));
            debugScope(logger, values);
        } else {
            logger.debug("INPUT DATASOURCE {} DOES NOT EXIST", name);
        }
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

    public void beforeClass() throws UnknownDataSourceTypeException {
        LOGGER.info("\n \n TESTWARE DATASOURCES AFTER SETUP - INFO DUMP -- START ");
        LOGGER.info("\n   NODES_TO_ADD {} \n", Iterables.toString(fromTafDataProvider(NODES_TO_ADD)).replace(", Data value: ", ",\nData value: "));
        LOGGER.info("\n   ADDED_NODES {} \n", Iterables.toString(context.dataSource(ADDED_NODES)).replace(", Data value: ", ",\nData value: "));
        LOGGER.info("\n   AVAILABLE_USERS {} \n", Iterables.toString(context.dataSource(AVAILABLE_USERS)).replace(", Data value: ", ",\nData value: "));
        LOGGER.info("\n \n TESTWARE DATASOURCES AFTER SETUP - INFO DUMP -- END ");
    }

    public void afterClass() {
    }
}
