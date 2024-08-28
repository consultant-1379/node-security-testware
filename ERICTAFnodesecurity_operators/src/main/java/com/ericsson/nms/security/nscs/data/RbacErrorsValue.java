/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.data;

/**
 * @author enmadmin
 */
public interface RbacErrorsValue extends SyntaxErrorValue {

    String getExpected();

    String[] getRoles();
}
