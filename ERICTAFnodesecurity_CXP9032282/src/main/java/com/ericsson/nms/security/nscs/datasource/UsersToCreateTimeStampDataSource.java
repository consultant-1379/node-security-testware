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
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseObjectForClearerAPI"})
public class UsersToCreateTimeStampDataSource {

    /**
     * Number of nodes have to be created.
     */
    public static final String NUM_OF_NODES = "nodes.amount";
    public static final String SUITE_NAME = "suite.name";

    public static final String UserPathTemp = "usersToCreateTemp";

    private static final String Roles = "roles";
    private static final String Description = "description";

    /**
     * Input for user to create DataSource.
     *
     * @return input for TestDataSource class
     */
    @DataSource
    public List<Map<String, Object>> createUser() {
        final String suiteName = "_" + System.getProperty(SUITE_NAME).replace("NSCS_", "").replaceAll(" ", "");
        final List<Map<String, Object>> result = new ArrayList<>();
        final TestDataSource<DataRecord> userList = TafDataSources.fromTafDataProvider(UserPathTemp);
        for (final DataRecord next : userList) {
            setTimeStamp(result, next, suiteName);
        }
        return result;
    }

    /**
     * Returns the user.
     *
     * @param username
     *         the username
     * @param password
     *         the password
     * @param firstName
     *         the first name
     * @param lastName
     *         the last name
     * @param email
     *         the email
     * @param enabled
     *         user enable state
     * @param description
     *         the user access rights
     * @param roles
     *         the user access rights
     *
     * @return the user
     */
    private Map<String, Object> getUser(final String suiteName, final String username, final String password, final String firstName, final String
            lastName,
            final String email, final boolean enabled, final String description, final String... roles) {
        final Map<String, Object> user = Maps.newHashMap();
        user.put("username", username);
        user.put("password", password);
        user.put("firstName", firstName);
        user.put("lastName", lastName);
        user.put("email", email);
        user.put(Roles, changeRoleName(suiteName, roles));
        user.put("enabled", enabled);
        user.put("description", description);
        return user;
    }

    private void setTimeStamp(final List<Map<String, Object>> list, final DataRecord data, final String suiteName) {
        final long nanoTime = System.nanoTime();
        final String user = String.format("%s%07d", data.getFieldValue("username"), nanoTime % 10000000);
        final String description = (data.getFieldValue(Description) != null) ? (String) data.getFieldValue(Description) : "";
        if (data.getFieldValue("roles") instanceof String[]) {
            list.add(getUser(suiteName, user, (String) data.getFieldValue("password"),
                    String.format("%sfirstname", user), String.format("%slastname", user),
                    String.format("%s@test.com", user), true, description,
                    (String[]) data.getFieldValue("roles")));
        }
        //TDM BUG
        else if (data.getFieldValue("roles") instanceof String) {
            list.add(getUser(suiteName, user, (String) data.getFieldValue("password"),
                    String.format("%sfirstname", user), String.format("%slastname", user),
                    String.format("%s@test.com", user), true, description,
                    ((String) data.getFieldValue("roles")).split(",")));
        }
    }

    private String[] changeRoleName(final String suiteName, final String... roles) {
        final String[] listUsed = new String[roles.length];
        for (int i = 0; i < roles.length; i++) {
            final String role = roles[i];
            if (role.contains("_role")) {
                listUsed[i] = role + suiteName;
            } else {
                listUsed[i] = role;
            }
        }
        return listUsed;
    }
}
