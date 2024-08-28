package com.ericsson.nms.security.nscs.utils;

import java.io.StringWriter;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.oss.testware.nodesecurity.data.issuexml.Nodes;
import com.ericsson.oss.testware.nodesecurity.data.issuexml.ObjectFactory;
import com.ericsson.oss.testware.nodesecurity.utils.exceptions.XmlComposerException;

/**
 * Created by enmadmin on 11/3/16.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class XmlComposerExt {

    public Nodes createXml(final List<DataRecord> values) {
        final ObjectFactory xmlFactory = new ObjectFactory();
        final Nodes nodes = xmlFactory.createNodes();
        for (final DataRecord value : values) {
            final Nodes.Node node = new Nodes.Node();
            node.setNodeFdn((String) value.getFieldValue("networkElementId"));
            setEnrollmentValue(node, (String) value.getFieldValue("enrollmentMode"));
            setEntityProfileName(node, (String) value.getFieldValue("entityProfileName"));
            setKeySize(node, (String) value.getFieldValue("keySize"));
            setSubjectAltName(node, (String) value.getFieldValue("subjectAltName"));
            setSubjectAltNameType(node, (String) value.getFieldValue("subjectAltNameType"));
            nodes.getNode().add(node);
        }
        return nodes;
    }

    public String marshal(final Nodes nodes) throws XmlComposerException {
        StringWriter sw = new StringWriter();
        try {
            final JAXBContext jaxbCtx = JAXBContext.newInstance(Nodes.class);
            final Marshaller marshaller = jaxbCtx.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            sw = new StringWriter();
            marshaller.marshal(nodes, sw);
        } catch (final JAXBException ex) {
            throw new XmlComposerException(ex);
        }
        return sw.toString();
    }

    private void setEnrollmentValue(final Nodes.Node node, final String fieldValue) {
        if (isNotEmpty(fieldValue)) {
            node.setEnrollmentMode(fieldValue);
        }
    }

    private void setEntityProfileName(final Nodes.Node node, final String fieldValue) {
        if (isNotEmpty(fieldValue)) {
            node.setEntityProfileName(fieldValue);
        }
    }

    private void setKeySize(final Nodes.Node node, final String fieldValue) {
        if (isNotEmpty(fieldValue)) {
            node.setKeySize(fieldValue);
        }
    }

    private void setSubjectAltName(final Nodes.Node node, final String fieldValue) {
        if (isNotEmpty(fieldValue)) {
            node.setSubjectAltName(fieldValue);
        }
    }

    private void setSubjectAltNameType(final Nodes.Node node, final String fieldValue) {
        if (isNotEmpty(fieldValue)) {
            node.setSubjectAltNameType(fieldValue);
        }
    }

    private boolean isNotEmpty(final String fieldValue) {
        return fieldValue != null && !fieldValue.isEmpty();
    }

}
