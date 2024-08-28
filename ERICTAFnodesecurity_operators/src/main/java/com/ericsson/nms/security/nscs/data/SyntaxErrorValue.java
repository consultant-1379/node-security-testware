/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.data;

import com.ericsson.oss.testware.enmbase.data.NetworkNode;

/**
 * @author teigrul
 */
public interface SyntaxErrorValue extends NetworkNode {

    String getCommand();

    String getPurpose();
}
