/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.combine;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;

/**
 * SetupAndTeardownScenarioRealNode necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public abstract class SetupAndTeardownCertTypeScenario extends SetupAndTeardownScenario {

    public static final String ISSUE = "ISSUE";

    static TestDataSource<DataRecord> oamDataSource;
    static TestDataSource<DataRecord> ipsecDataSource;

    public static TestDataSource<DataRecord> getOamDataSource() {
        return oamDataSource;
    }

    public static TestDataSource<DataRecord> getIpsecDataSource() {
        return ipsecDataSource;
    }

    public static int getNumUserOam() {
        final int size = Iterables.size(getOamDataSource());
        return (size > 0) ? size : 1;
    }

    public static int getNumUserIpsec() {
        final int size = Iterables.size(getIpsecDataSource());
        return (size > 0) ? size : 1;
    }

    @Override
    protected void setupSpecificDataSource() {
        final TestDataSource<DataRecord> issue = fromTafDataProvider("issue");
        final Iterable<DataRecord> issueFiltered =
                Iterables.filter(issue, PredicateUtil.suiteNamePredicate("suiteName", getSuiteName()));
        SetupAndTearDownUtil.removeAndCreateTestDataSource(ISSUE, issueFiltered);
        ScenarioUtility.debugScope(getLogger(), ISSUE);
    }

    protected void prepareCertTypeDataSource() {
        oamDataSource = TestDataSourceFactory.createDataSource();
        ipsecDataSource = TestDataSourceFactory.createDataSource();
        final Predicate<DataRecord> subSetTestRfa250 = SetupAndTeardownScenario.isRfa250()
                ? PredicateUtil.rfa250Predicate() : PredicateUtil.passTrue();
        final Predicate<DataRecord> oamType = PredicateUtil.genericPredicate("certType", Arrays.asList("OAM"));
        final Predicate<DataRecord> ipsecType = PredicateUtil.genericPredicate("certType", Arrays.asList("IPSEC"));
        final List<String> nodeList = new ArrayList<>();
        final TestDataSource<DataRecord> nodeDataSource = context.dataSource(NODES_TO_ADD);
        for (final DataRecord node : nodeDataSource) {
            final String nodetype = node.getFieldValue("nodeType");
            if (!nodeList.contains(nodetype)) {
                nodeList.add(nodetype);
            }
        }
        for (final String nodeTypeValue : nodeList) {
            final Predicate<DataRecord> nodeType = PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypeValue));
            final Predicate<DataRecord> oamTypeNodeType = Predicates.and(oamType, nodeType);
            final Predicate<DataRecord> ipsecTypeNodeType = Predicates.and(ipsecType, nodeType);
            final TestDataSource<DataRecord> addedNodesFiltered = TafDataSources.filter(nodeDataSource, nodeType);
            ScenarioUtility.debugScope(getLogger(), addedNodesFiltered);
            final TestDataSource<DataRecord> oamFiltered = TafDataSources.filter(context.dataSource(ISSUE), oamTypeNodeType);
            ScenarioUtility.debugScope(getLogger(), oamFiltered);
            oamDataSource = combine(oamDataSource, generateNodesCertType(addedNodesFiltered, TafDataSources.filter(oamFiltered, subSetTestRfa250)));
            ScenarioUtility.debugScope(getLogger(), oamDataSource);
            final TestDataSource<DataRecord> ipsecFiltered = TafDataSources.filter(context.dataSource(ISSUE), ipsecTypeNodeType);
            ScenarioUtility.debugScope(getLogger(), ipsecFiltered);
            ipsecDataSource = combine(ipsecDataSource, generateNodesCertType(addedNodesFiltered, TafDataSources.filter(ipsecFiltered,
                    subSetTestRfa250)));
            ScenarioUtility.debugScope(getLogger(), ipsecDataSource);
        }
        ScenarioUtility.debugScope(getLogger(), oamDataSource);
        ScenarioUtility.debugScope(getLogger(), ipsecDataSource);
    }

    private TestDataSource<DataRecord> generateNodesCertType(final TestDataSource<DataRecord> nodes, final TestDataSource<DataRecord> oamipsec) {
        if (Iterables.size(nodes) != 1 && Iterables.size(oamipsec) == 1) {
            final DataRecord oamIpsecValue = Iterables.getFirst(oamipsec, null);
            final TestDataSource<DataRecord> nodesListReadFromDataProvider = TestDataSourceFactory.createDataSource();
            for (final DataRecord nodeInfo : nodes) {
                nodesListReadFromDataProvider.addRecord().setFields(nodeInfo).setFields(oamIpsecValue);
            }
            return nodesListReadFromDataProvider;
        } else {
            return merge(oamipsec, nodes);
        }
    }

    @Override
    protected boolean isSlGetRequested() {
        return isAgat();
    }

    @Override
    protected void scenarioSetupAfterBeforeSuite() {
        prepareCertTypeDataSource();
    }
}
