package com.ericsson.nms.security.nscs.data;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @author ecappie
 */
public interface AddIscfPositiveIPSecValue extends AddIscfPositiveValue {

    String getIpsecUserLabel();

    String getSubjectAltName();

    String getSubjectAltNameType();

    String getIpsecAreas();

    String getExpectedIpsecNodeCredentialId();

    String getExpectedIpsecTrustCategoryId();
}