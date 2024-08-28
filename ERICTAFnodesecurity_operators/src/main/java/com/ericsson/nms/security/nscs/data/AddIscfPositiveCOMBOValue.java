package com.ericsson.nms.security.nscs.data;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @author ecappie
 */
public interface AddIscfPositiveCOMBOValue extends AddIscfPositiveValue {

    String getWantedSecLevel();

    String getMinimumSecLevel();

    String getIpsecUserLabel();

    String getSubjectAltName();

    String getSubjectAltNameType();

    String getIpsecAreas();

    String getExpectedKeyLength2();

    String getExpectedEnrolMode2();

    String getExpectedDistinguishedName2();

    String getExpectedCertificateAuthorityDn2();

    String getExpectedOamNodeCredentialId();

    String getExpectedIpsecNodeCredentialId();

    String getExpectedOamTrustCategoryId();

    String getExpectedIpsecTrustCategoryId();
}
