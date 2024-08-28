package com.ericsson.nms.security.nscs.utils;

import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.FM_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.VNFMS_TO_ADD;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestNGMethod;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.handlers.netsim.domain.NetworkElement;
import com.ericsson.cifwk.taf.scenario.TestScenarios;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.oss.testware.enmbase.data.TargetCategory;
import com.ericsson.oss.testware.fm.api.datarecord.FmNode;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.AvoidCatchingGenericException", "PMD.ClassNamingConventions"})
public final class Utils {

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    private Utils() {
    }

    public static String getDeleteNodes() {
        return DataHandler.getConfiguration().getProperty("nscs.deletenodes", SecurityConstants.DELETENODES_DEFAULT, String.class);
    }

    /**
     * The following method retrieves the path to look for csv files used to run the test according to the enviroment used (physical, vApps, etc.)
     */
    public static String getSourcePath() {
        final String path = "data" + File.separator + "profiles" + File.separator;
        log.info("Loaded profile path [{}]", path);
        return path;
    }

    public static List<String> generateNodeNames(final String nodeNames) {
        if (nodeNames != null) {
            if (nodeNames.contains("@@@")) {
                return generateNodeNamesByRange(nodeNames);
            }
            return generateNodeNamesBySemiColon(nodeNames);
        }
        return null;
    }

    private static List<String> generateNodeNamesByRange(final String nodeNames) {
        final List<String> nodeList = new ArrayList<>();
        if (nodeNames != null) {
            final String[] nodes = nodeNames.split("@@@");
            if (nodes.length > 1) {
                final String startNodeName = nodes[0];
                final String endNodeName = nodes[1];
                int startIdx = Integer.parseInt(startNodeName.substring(startNodeName.length() - 3, startNodeName.length()));
                final int endIdx = Integer.parseInt(endNodeName.substring(endNodeName.length() - 3, endNodeName.length()));
                log.debug("startIdx [{}] --- endIdx [{}]", startIdx, endIdx);
                while (startIdx <= endIdx) {
                    final String lteName = startNodeName.substring(0, startNodeName.length() - 3) + String.format("%03d", startIdx);
                    nodeList.add(lteName);
                    startIdx += 1;
                }
            }
        }
        return nodeList;
    }

    private static List<String> generateNodeNamesBySemiColon(final String nodeNames) {
        final List<String> nodeList = new ArrayList<>();
        if (nodeNames != null) {
            for (final String n : nodeNames.split(";")) {
                nodeList.add(n);
            }
        }
        return nodeList;
    }

    public static List<Map<String, Object>> copyDataSource(final TestDataSource<DataRecord> inputDS, final String dataSourceName) {
        final List<Map<String, Object>> iterableDataSource = Lists.newArrayList();
        TestScenarios.resetDataSource(dataSourceName);
        if (inputDS != null) {
            try {
                for (final DataRecord ds : Lists.newArrayList(inputDS.iterator())) {
                    final Map<String, Object> fields = Maps.newHashMap(ds.getAllFields());
                    iterableDataSource.add(fields);
                }
            } catch (final Exception ex) {
                log.error(ex.getMessage(), ex);
            }
        }
        return iterableDataSource;
    }

    public static String extractHostName(final NetworkElement networkElement) {
        final String hostName;
        final String[] hostNames = networkElement.getHostName().split("\\s");
        if (hostNames.length > 1) {
            hostName = hostNames[1];
        } else {
            hostName = hostNames[0];
        }
        return hostName;
    }

    /*
     * XML Utils
     */

    /**
     * Given an XML content passed as String and begin and ends tags, extract a section between them (with both tags included)
     *
     * @param xmlString
     *         the content of the XML file, passed as a String
     * @param tagBegin
     *         the begin tag (E.g.: "<secEnrollmentData")
     * @param tagEnd
     *         the end tag (E.g.: "secEnrollmentData>")
     *
     * @return a subString containing the XML section between begin and end tags, both tags included
     */
    public static String extractTagSectionFromXmlString(final String xmlString, final String tagBegin, final String tagEnd) {
        final int a = getIndexOfTagInXmlString(xmlString, tagBegin);
        final int z = getIndexOfTagInXmlString(xmlString, tagEnd);
        final int tagEndLength = tagEnd.length();
        final String subString = xmlString.substring(a, z + tagEndLength);
        log.debug("\nGot substring: " + subString + "\n(between tagBegin: " + tagBegin + " and tagEnd: " + tagEnd);
        return subString;
    }

    /**
     * Get the index of tag in XML content, provided as a String
     *
     * @param xmlString
     *         the content of the XML file, passed as a String
     * @param tagName
     *         the name of the tag
     *
     * @return indexOfTagInXmlContent
     */
    public static int getIndexOfTagInXmlString(final String xmlString, final String tagName) {
        final int indexOfTagInXmlContent = xmlString.indexOf(tagName);
        log.debug("indexOfTag " + tagName + "in xmlContent: " + indexOfTagInXmlContent);
        return indexOfTagInXmlContent;
    }

    /**
     * Initialise fm nodes.
     */
    public static void initFmNodes() {
        final TestContext localContext = TafTestContext.getContext();
        // TODO Need to sort out user of context here and in extened classes
        if (localContext.doesDataSourceExist(NODES_TO_ADD)) {
            final TestDataSource<DataRecord> list = localContext.dataSource(NODES_TO_ADD);
            final Iterator<DataRecord> iterator = list.iterator();
            for (final Iterator iterator1 = iterator; iterator.hasNext(); ) {
                final DataRecord next = (DataRecord) iterator1.next();
                final Map<String, Object> record = new HashMap<>();
                record.put("targetCategory", TargetCategory.NODE.toString());
                record.put("genericType", next.getFieldValue("nodeType"));
                record.put("genericId", next.getFieldValue("networkElementId"));
                record.put("active", true);
                record.put("subscriptionState", "ENABLED");
                record.put("expectedMessage", "");
                final DataRecordImpl newDataRecord = new DataRecordImpl(record);
                localContext.dataSource(FM_NODES, FmNode.class).addRecord().setFields(newDataRecord);
            }
        } else if (localContext.doesDataSourceExist(VNFMS_TO_ADD)) {
            final TestDataSource<DataRecord> list = localContext.dataSource(VNFMS_TO_ADD);
            final Iterator<DataRecord> iterator = list.iterator();
            for (final Iterator iterator1 = iterator; iterator.hasNext(); ) {
                final DataRecord next = (DataRecord) iterator1.next();
                final Map<String, Object> record = new HashMap<>();
                record.put("targetCategory", TargetCategory.VNFM.toString());
                record.put("genericType", next.getFieldValue("vmType"));
                record.put("genericId", next.getFieldValue("virtualNetworkFuncMngId"));
                final DataRecordImpl newDataRecord = new DataRecordImpl(record);
                localContext.dataSource(FM_NODES, FmNode.class).addRecord().setFields(newDataRecord);
            }
        }
        TafDataSources.shared(localContext.dataSource(FM_NODES));
    }

    /**
     * @param datasourceName
     *         Usage: showDatasourceInTestContext(USERS_TO_CREATE);
     */
    public static void showDatasourceInTestContext(final String datasourceName) {
        // From fmInitNodes()...
        final TestContext localContext = TafTestContext.getContext();
        // ...but was, in the caller:
        /*
         * @Inject private TestContext context;
         */

        // The dataSource = list of Rows
        final TestDataSource<DataRecord> list = localContext.dataSource(datasourceName);

        // One Row (the 1st one)
        final Iterator<DataRecord> iterator = list.iterator();

        for (final Iterator iterator1 = iterator; iterator.hasNext(); ) {
            // One row (after the first)
            final DataRecord next = (DataRecord) iterator1.next();
            printDatarecord(next);
        }
    }

    /**
     * @param dataRecord
     *      the DataRecord (DataSource row) to print
     */
    public static void printDatarecord(final DataRecord dataRecord) {
        final Map<String, Object> theRow = dataRecord.getAllFields();
        printMapStringObject(theRow);
    }

    /**
     *
     * @param map
     */
    public static void printMapStringObject(final Map<String, Object> map) {
        for (final Map.Entry<String, Object> entry : map.entrySet()) {
            log.debug("Key: [{}] Value: [{}]", entry.getKey(), entry.getValue());
        }
    }

    //
    // ecappie's additions
    //

    // https://stackoverflow.com/questions/3598770/check-whether-a-string-is-not-null-and-not-empty,
    //   first answer (flagged)
    public static boolean empty( final String s ) {
        // Null-safe, short-circuit evaluation.
        return s == null || s.trim().isEmpty();
    }

    // From https://stackoverflow.com/questions/409784/whats-the-simplest-way-to-print-a-java-array,
    // see comment redirecting to http://www.javahotchocolate.com/notes/java.html#arrays-tostring
    // Title:  Arrays.toString() minus the brackets
    // Reason: Arrays.toString(array) surrounds the whole with "[ ... ]" -- not what we want.
    public static String returnStringFromArrayOfString(final String[] array)
    {
        final StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (final String particle : array) {
            if( !first ) {
                sb.append(' ');
            }
            sb.append(particle);
            first = false;
        }
        return sb.toString();
    }

    // DISPLAY a LIST of String
    // https://stackoverflow.com/questions/10168066/how-to-print-out-all-the-elements-of-a-list-in-java,
    //   second response (shorter, and additional nice ',')
    // Note: list.toString() produces the same output
    public static String returnStringFromListOfString(final List<String> list) {
        return Arrays.toString(list.toArray());
    }

    // PRINT a SET of String
    // From: https://beginnersbook.com/2014/08/how-to-iterate-over-a-sethashset/

    // Way 1 - Without using Iterator
    public static void logSetOfString(final Set<String> set) {
        for (final String temp : set) {
            log.debug("\n  [{}]", temp);
        }
    }
    // Way 2 - Using Iterator
    public static void logSetOfStringWithIterator(final Set<String> set) {
        final Iterator<String> it = set.iterator();
        while(it.hasNext()) {
            log.debug("\n  [{}]", it.next());
        }
    }

    // PRINT the names of all TestNG methods - from array
    public static void logITestNGMethodsNamesFromArray(final ITestNGMethod[] allTestMethodsArray) {
        for (final ITestNGMethod item : allTestMethodsArray) {
            log.debug("\n  [{}]", item.getMethodName());
        }
    }

    // PRINT the names of all TestNG methods - from collection
    public static void logITestNGMethodsNamesFromCollection(final Collection<ITestNGMethod> allTestMethodsCollection) {
        for(final ITestNGMethod item : allTestMethodsCollection) {
            log.debug("\n  [{}]", item.getMethodName());
        }
    }
}
