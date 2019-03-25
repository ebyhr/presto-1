/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.prestosql.plugin.cassandra;

import io.airlift.log.Logger;
import io.prestosql.plugin.cassandra.util.CassandraCqlUtils;
import io.prestosql.spi.connector.ColumnHandle;
import io.prestosql.spi.connector.ConnectorRecordSetProvider;
import io.prestosql.spi.connector.ConnectorSession;
import io.prestosql.spi.connector.ConnectorSplit;
import io.prestosql.spi.connector.ConnectorTableHandle;
import io.prestosql.spi.connector.ConnectorTransactionHandle;
import io.prestosql.spi.connector.RecordSet;

import javax.inject.Inject;

import java.util.List;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;

public class CassandraRecordSetProvider
        implements ConnectorRecordSetProvider
{
    private static final Logger log = Logger.get(CassandraRecordSetProvider.class);

    private final CassandraSession cassandraSession;

    @Inject
    public CassandraRecordSetProvider(CassandraSession cassandraSession)
    {
        this.cassandraSession = requireNonNull(cassandraSession, "cassandraSession is null");
    }

    @Override
    public RecordSet getRecordSet(ConnectorTransactionHandle transaction, ConnectorSession session, ConnectorSplit split, ConnectorTableHandle table, List<? extends ColumnHandle> columns)
    {
        CassandraSplit cassandraSplit = (CassandraSplit) split;
        CassandraTableHandle cassandraTable = (CassandraTableHandle) table;

        List<CassandraColumnHandle> cassandraColumns = columns.stream()
                .map(column -> (CassandraColumnHandle) column)
                .collect(toList());

        String selectCql = CassandraCqlUtils.selectFrom(cassandraTable, cassandraColumns).getQueryString();
        StringBuilder sb = new StringBuilder(selectCql);
        if (sb.charAt(sb.length() - 1) == ';') {
            sb.setLength(sb.length() - 1);
        }
        sb.append(cassandraSplit.getWhereClause());
        String cql = sb.toString();
        log.debug("Creating record set: %s", cql);
        System.out.println(cql);

        return new CassandraRecordSet(cassandraSession, cql, cassandraColumns);
    }
}
