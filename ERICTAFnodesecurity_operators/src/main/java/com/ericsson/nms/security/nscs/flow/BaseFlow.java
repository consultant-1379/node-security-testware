/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NETWORK_ELEMENT_ID;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NODE_INDEX;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NODE_TYPE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import java.util.List;
import java.util.Map;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.api.TafDataSourceDefinitionBuilder;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.enmbase.provider.DefaultNodeSecurityProvider;
import com.google.common.collect.Lists;

/**
 * Util method for class flows.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseObjectForClearerAPI", "PMD.DoNotUseThreads"})
public class BaseFlow {

    private static final Logger log = LoggerFactory.getLogger(BaseFlow.class);

    @Inject
    TestContext context;

    protected Runnable addNodeTypeToDataSource(final String inputCsv, final String inputDataSourceName, final String outputDataSourceName,
            final String defaultNodeType) {
        return new Runnable() {
            @Override
            public void run() {
                context.addDataSource(outputDataSourceName,
                        TestDataSourceFactory.createDataSource(fillListOfRows(inputCsv, inputDataSourceName, defaultNodeType)));
            }
        };
    }

    /**
     * Read input csv and return a list with all csv values. In addition node type, default credentials, networkElementId are added to the datasource.
     *
     * @param inputCsv
     *         input csv
     * @param inputDataSourceName
     *         input data source name
     * @param defaultNodeType
     *         default node type
     *
     * @return List of map objects with all csv values and furthermore node type, default credentials, networkElementId.
     */
    public List<Map<String, Object>> fillListOfRows(final String inputCsv, final String inputDataSourceName, final String defaultNodeType) {
        final String sourcePath = Utils.getSourcePath();
        log.debug("loading csv [{}]", sourcePath + inputCsv);
        context.addDataSource(inputDataSourceName, fromCsv(sourcePath + inputCsv));
        final List<Map<String, Object>> rows = Utils.copyDataSource(context.dataSource(inputDataSourceName), inputDataSourceName);
        for (final Map<String, Object> row : rows) {
            final String nodeIndexValue = (String) row.get(NODE_INDEX);
            final String nodeName = (String) DataHandler.getConfiguration().getProperty(NODE_INDEX + "." + nodeIndexValue);
            row.put(NETWORK_ELEMENT_ID, nodeName);
            for (final DataRecord ds : Lists.newArrayList(context.dataSource(ADDED_NODES).iterator())) {
                row.put(NODE_TYPE, defaultNodeType);
                if (nodeName != null && nodeName.equals(ds.getFieldValue(NETWORK_ELEMENT_ID))) {
                    row.put(NODE_TYPE, ds.getFieldValue(NODE_TYPE));
                    row.put(DefaultNodeSecurityProvider.NORMAL_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    row.put(DefaultNodeSecurityProvider.NORMAL_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    row.put(DefaultNodeSecurityProvider.ROOT_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    row.put(DefaultNodeSecurityProvider.ROOT_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    row.put(DefaultNodeSecurityProvider.SECURE_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    row.put(DefaultNodeSecurityProvider.SECURE_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
                    break;
                }
            }
        }
        return rows;
    }

    public List<Map<String, Object>> fillListOfRowsShort(final String inputCsv, final String inputDataSourceName, final String defaultNodeType) {
        final String sourcePath = Utils.getSourcePath();
        log.debug("loading csv [{}]", sourcePath + inputCsv);
        context.addDataSource(inputDataSourceName, fromCsv(sourcePath + inputCsv));
        final List<Map<String, Object>> rows = Utils.copyDataSource(context.dataSource(inputDataSourceName), inputDataSourceName);
        for (final Map<String, Object> row : rows) {
            for (final DataRecord ds : Lists.newArrayList(context.dataSource(ADDED_NODES).iterator())) {
                row.put(NODE_TYPE, defaultNodeType);
                if (ds.getFieldValue(NETWORK_ELEMENT_ID) != null) {
                    row.put(NODE_TYPE, ds.getFieldValue(NODE_TYPE));
                    break;
                }
            }
        }
        return rows;
    }

    public TafDataSourceDefinitionBuilder fillDataSource(final String inputCsv, final String inputDataSourceName, final String outputDataSourceName,
            final String defaultNodeType) {
        context.addDataSource(outputDataSourceName,
                TestDataSourceFactory.createDataSource(fillListOfRows(inputCsv, inputDataSourceName, defaultNodeType)));
        return new TafDataSourceDefinitionBuilder(outputDataSourceName, DataRecord.class);
    }

    public TafDataSourceDefinitionBuilder fillDataSourceShort(final String inputCsv, final String inputDataSourceName, final String outputDataSourceName,
            final String defaultNodeType) {
        context.addDataSource(outputDataSourceName,
                TestDataSourceFactory.createDataSource(fillListOfRowsShort(inputCsv, inputDataSourceName, defaultNodeType)));
        return new TafDataSourceDefinitionBuilder(outputDataSourceName, DataRecord.class);
    }

    protected Runnable addDataSourceFromCsv(final String inputCsv, final String inputDataSourceName) {
        return new Runnable() {
            @Override
            public void run() {
                final String sourcePath = Utils.getSourcePath();
                log.debug("loading csv [{}]", sourcePath + inputCsv);
                context.addDataSource(inputDataSourceName, fromCsv(sourcePath + inputCsv));
            }
        };
    }

    protected Runnable resetDataSource(final String datasourceName) {
        return new Runnable() {
            @Override
            public void run() {
                context.removeDataSource(datasourceName);
            }
        };
    }
}
