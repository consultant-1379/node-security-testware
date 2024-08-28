package com.ericsson.nms.security.nscs.data;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import com.ericsson.cifwk.taf.datasource.DataRecord;

/**
 * @author ecappie
 */
public interface AddIscfNegativeValue extends DataRecord {

    String getUseCase();

    String getLogicalName();

    String getNodeFdn();

    String getWantedEnrolMode();

    String getNodeType();

    String getMimVersion();

    String getExpectedExceptionSubstring();
}
