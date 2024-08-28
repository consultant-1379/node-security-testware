/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.data;

import com.ericsson.cifwk.taf.datasource.DataRecord;

public interface CliScriptingValue extends DataRecord {

    String getScriptFile();

    String getScriptParams();

}
