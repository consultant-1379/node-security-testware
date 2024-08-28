package com.ericsson.nms.security.nscs.data;

import com.ericsson.oss.testware.nodesecurity.data.ExtNetworkNode;

public interface GetCredentialsValue extends ExtNetworkNode {

    String getCommand();

    String getExpectedMsg();

    String getFileName();

    String getSuggestedSolution();

    String getExpectedResponse1();

    String getExpectedResponse2();

    String getSuiteProfile();

    String getCertType();

    String getCaName();

    String getTrustProfile();

    String getEntityProfile();

}
