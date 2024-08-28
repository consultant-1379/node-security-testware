package com.ericsson.nms.security.nscs.utils;

import static com.ericsson.nms.security.nscs.constants.SecurityConstants.PROFILE_EXTRA;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.PROFILE_FULL;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.PROFILE_MAINTRACK;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.PROFILE_SETUP;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SUITE_PROFILE;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.execution.InitialTestContext;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;

/**
 * Created by emazste on 12/20/16.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ImmutableField"})
public final class UtilContext {

    private static final String NSCS_PROFILES_PROPERTIES = "nscs.profiles";

    private static UtilContext utilContext;

    private TestContext context = new InitialTestContext(); // TODO remove "PMD.ImmutableField"

    private UtilContext() {
    }

    public static UtilContext makeUtilContext() {
        if (utilContext == null) {
            utilContext = new UtilContext();
        }
        return utilContext;
    }

    public String readSuiteProfile() {
        return context.getAttribute(SUITE_PROFILE);
    }

    /**
     * Set the nscs.profiles property as the greater than
     *
     * @param suiteNscsProfiles
     *         profile name
     */
    public void setProfile(final String suiteNscsProfiles) {
        if (calcSuiteProfileLevel(suiteNscsProfiles) >= calcSuiteProfileLevel(readNscsProfileProperties())) {
            storeSuiteProfile(suiteNscsProfiles);
        }
    }

    private void storeSuiteProfile(final String suiteProfileValue) {
        context.setAttribute(SUITE_PROFILE, suiteProfileValue);
    }

    private String readNscsProfileProperties() {
        return DataHandler.getConfiguration().getProperty(NSCS_PROFILES_PROPERTIES, SecurityConstants.PROFILE_MAINTRACK, String.class);
    }

    private int calcSuiteProfileLevel(final String suiteProfile) {
        switch (suiteProfile) {
            case PROFILE_SETUP:
                return 3;
            case PROFILE_FULL:
                return 2;
            case PROFILE_EXTRA:
                return 1;
            case PROFILE_MAINTRACK:
                return 0;
            default:
                return -1;
        }
    }
}
