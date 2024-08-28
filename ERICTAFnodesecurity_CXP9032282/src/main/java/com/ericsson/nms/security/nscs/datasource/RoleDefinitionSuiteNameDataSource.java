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

package com.ericsson.nms.security.nscs.datasource;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.ericsson.cifwk.taf.annotations.DataSource;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.google.common.collect.Maps;

/**
 * UsersToCreateDataSource class for users creation data.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class RoleDefinitionSuiteNameDataSource {

    /**
     * Number of nodes have to be created.
     */
    public static final String SUITE_NAME = "suite.name";

    public static final String UserPathTemp = "roleToCreateTemp";

    private static final String name = "name";

    /**
     * Input for user to create DataSource.
     *
     * @return input for TestDataSource class
     */
    @DataSource
    public List<Map<String, Object>> createRoles() {
        final String suiteName = "_" + System.getProperty(SUITE_NAME).replace("NSCS_", "").replaceAll(" ", "");
        final List<Map<String, Object>> result = new ArrayList<>();
        final TestDataSource<DataRecord> roleList = TafDataSources.fromTafDataProvider(UserPathTemp);
        for (final DataRecord next : roleList) {
                setSuiteName(result, next, suiteName);
        }
        return result;
    }

    private void setSuiteName(final List<Map<String, Object>> list, final DataRecord data, final String suiteName) {
        final Map<String, Object> newdata = Maps.newHashMap(data.getAllFields());
        newdata.put(name, data.getFieldValue(name)+suiteName);
        list.add(newdata);
    }
}
