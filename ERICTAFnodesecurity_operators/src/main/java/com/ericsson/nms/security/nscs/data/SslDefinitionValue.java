package com.ericsson.nms.security.nscs.data;

import com.ericsson.cifwk.taf.datasource.DataRecord;

public interface SslDefinitionValue extends DataRecord {

    String getSslDefinitionName();

    String getSslDefinitionDescr();

    String getSslDefinitionClientVerify();

    String getSslDefinitionClientDepth();

    String getSslDefinitionServerVerify();

    String getSslDefinitionServerDepth();

    String getSslDefinitionProtocolVersion();

    String getSslDefinitionClientCertFile();

    String getSslDefinitionClientCACertFile();

    String getSslDefinitionClientKeyFile();

    String getSslDefinitionClientPassword();

    String getSslDefinitionServerCertFile();

    String getSslDefinitionServerCACertFile();

    String getSslDefinitionServerKeyFile();

    String getSslDefinitionServerPassword();

    String getSslDefinitionNodeNames();
}
