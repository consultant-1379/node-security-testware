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

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.ericsson.cifwk.taf.annotations.DataSource;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.oss.testware.enmbase.data.ENMUser;
import com.google.common.collect.Maps;

/**
 * UsersToCreateDataSource class for users creation data.
 */
//TODO (ekeimoo): enm-security-test-library has implemented createUserWithPrefix which will eliminated the need for this class
//TODO (ecappie): This class is used only by NodeSecurity_SL2.xml suite by Ciphers team - Explore solution (also for lib method), and remove this
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseObjectForClearerAPI"})
public class UsersToCreateDataSource {

    /**
     * Number of nodes have to be created.
     */
    public static final String NUM_OF_NODES = "nodes.amount";
    public static final Integer NUM_OF_USERS = DataHandler.getConfiguration().getProperty(NUM_OF_NODES, 2, Integer.class);

    private static final String Userpath = "data" + File.separator + "sl2" + File.separator + "SL2usersToCreate.csv";

    /**
     * Input for user to create DataSource.
     * 
     * @return input for TestDataSource class
     */
    @DataSource
    public List<Map<String, Object>> createUser() {
        final List<Map<String, Object>> result = new ArrayList<>();
        final TestDataSource<ENMUser> userList = TafDataSources.fromCsv(Userpath, ENMUser.class);
        for (final ENMUser next : userList) {
            for (int i = 1; i <= NUM_OF_USERS; i++) {
                final long nanoTime = System.nanoTime();
                final String user = String.format("%s%04d", next.getUsername(), nanoTime % 10000);
                result.add(getUser(user, String.format("%spw", user), String.format("%sfirstname", user), String.format("%slastname", user),
                        String.format("%s@test.com", user), true, next.getRoles()));
            }
        }
        return result;
    }

    /**
     * Returns the user.
     * 
     * @param username
     *            the username
     * @param password
     *            the password
     * @param firstName
     *            the first name
     * @param lastName
     *            the last name
     * @param email
     *            the email
     * @param enabled
     *            user enable state
     * @param roles
     *            the user access rights
     * @return the user
     */
    private Map<String, Object> getUser(final String username, final String password, final String firstName, final String lastName,
                                        final String email, final boolean enabled, final String... roles) {
        final Map<String, Object> user = Maps.newHashMap();
        user.put("username", username);
        user.put("password", password);
        user.put("firstName", firstName);
        user.put("lastName", lastName);
        user.put("email", email);
        user.put("roles", roles);
        user.put("enabled", enabled);
        return user;
    }
}
