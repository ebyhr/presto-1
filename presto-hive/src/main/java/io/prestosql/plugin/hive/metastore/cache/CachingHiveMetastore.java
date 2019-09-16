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
package io.prestosql.plugin.hive.metastore.cache;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.SetMultimap;
import com.google.common.util.concurrent.UncheckedExecutionException;
import io.airlift.units.Duration;
import io.prestosql.plugin.hive.HiveType;
import io.prestosql.plugin.hive.PartitionStatistics;
import io.prestosql.plugin.hive.authentication.HiveContext;
import io.prestosql.plugin.hive.metastore.Database;
import io.prestosql.plugin.hive.metastore.HiveMetastore;
import io.prestosql.plugin.hive.metastore.HivePartitionName;
import io.prestosql.plugin.hive.metastore.HivePartitionNameWithContext;
import io.prestosql.plugin.hive.metastore.HivePrincipal;
import io.prestosql.plugin.hive.metastore.HivePrivilegeInfo;
import io.prestosql.plugin.hive.metastore.HiveTableName;
import io.prestosql.plugin.hive.metastore.HiveTableNameWithContext;
import io.prestosql.plugin.hive.metastore.Partition;
import io.prestosql.plugin.hive.metastore.PartitionFilterWithContext;
import io.prestosql.plugin.hive.metastore.PartitionWithStatistics;
import io.prestosql.plugin.hive.metastore.PrincipalPrivileges;
import io.prestosql.plugin.hive.metastore.Table;
import io.prestosql.plugin.hive.metastore.TablesWithParameterCacheKey;
import io.prestosql.plugin.hive.metastore.UserTableKey;
import io.prestosql.spi.PrestoException;
import io.prestosql.spi.security.RoleGrant;
import io.prestosql.spi.statistics.ColumnStatisticType;
import io.prestosql.spi.type.Type;
import org.weakref.jmx.Managed;

import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.function.Function;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Throwables.throwIfInstanceOf;
import static com.google.common.base.Throwables.throwIfUnchecked;
import static com.google.common.cache.CacheLoader.asyncReloading;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.collect.ImmutableSetMultimap.toImmutableSetMultimap;
import static com.google.common.collect.Iterables.transform;
import static com.google.common.collect.Streams.stream;
import static com.google.common.util.concurrent.MoreExecutors.newDirectExecutorService;
import static io.prestosql.plugin.hive.HiveErrorCode.HIVE_PARTITION_DROPPED_DURING_QUERY;
import static io.prestosql.plugin.hive.metastore.HivePartitionNameWithContext.hivePartitionNameWithContext;
import static io.prestosql.plugin.hive.metastore.HiveTableName.hiveTableName;
import static io.prestosql.plugin.hive.metastore.HiveTableNameWithContext.hiveTableNameWithContext;
import static io.prestosql.plugin.hive.metastore.PartitionFilter.partitionFilter;
import static io.prestosql.plugin.hive.metastore.PartitionFilterWithContext.partitionFilterWithContext;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * Hive Metastore Cache
 */
@ThreadSafe
public class CachingHiveMetastore
        implements HiveMetastore
{
    protected final HiveMetastore delegate;
    private final LoadingCache<String, Optional<Database>> databaseCache;
    private final LoadingCache<String, List<String>> databaseNamesCache;
    private final LoadingCache<HiveTableNameWithContext, Optional<Table>> tableCache;
    private final LoadingCache<String, List<String>> tableNamesCache;
    private final LoadingCache<TablesWithParameterCacheKey, List<String>> tablesWithParameterCache;
    private final LoadingCache<HiveTableNameWithContext, PartitionStatistics> tableStatisticsCache;
    private final LoadingCache<HivePartitionNameWithContext, PartitionStatistics> partitionStatisticsCache;
    private final LoadingCache<String, List<String>> viewNamesCache;
    private final LoadingCache<HivePartitionNameWithContext, Optional<Partition>> partitionCache;
    private final LoadingCache<PartitionFilterWithContext, Optional<List<String>>> partitionFilterCache;
    private final LoadingCache<HiveTableNameWithContext, Optional<List<String>>> partitionNamesCache;
    private final LoadingCache<UserTableKey, Set<HivePrivilegeInfo>> tablePrivilegesCache;
    private final LoadingCache<String, Set<String>> rolesCache;
    private final LoadingCache<HivePrincipal, Set<RoleGrant>> roleGrantsCache;

    @Inject
    public CachingHiveMetastore(@ForCachingHiveMetastore HiveMetastore delegate, @ForCachingHiveMetastore Executor executor, CachingHiveMetastoreConfig config)
    {
        this(
                delegate,
                executor,
                config.getMetastoreCacheTtl(),
                config.getMetastoreRefreshInterval(),
                config.getMetastoreCacheMaximumSize());
    }

    public CachingHiveMetastore(HiveMetastore delegate, Executor executor, Duration cacheTtl, Duration refreshInterval, long maximumSize)
    {
        this(
                delegate,
                executor,
                OptionalLong.of(cacheTtl.toMillis()),
                refreshInterval.toMillis() >= cacheTtl.toMillis() ? OptionalLong.empty() : OptionalLong.of(refreshInterval.toMillis()),
                maximumSize);
    }

    public static CachingHiveMetastore memoizeMetastore(HiveMetastore delegate, long maximumSize)
    {
        return new CachingHiveMetastore(
                delegate,
                newDirectExecutorService(),
                OptionalLong.empty(),
                OptionalLong.empty(),
                maximumSize);
    }

    private CachingHiveMetastore(HiveMetastore delegate, Executor executor, OptionalLong expiresAfterWriteMillis, OptionalLong refreshMills, long maximumSize)
    {
        this.delegate = requireNonNull(delegate, "delegate is null");
        requireNonNull(executor, "executor is null");

        databaseNamesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadAllDatabases), executor));

        databaseCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadDatabase), executor));

        tableNamesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadAllTables), executor));

        tablesWithParameterCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadTablesMatchingParameter), executor));

        tableStatisticsCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(new CacheLoader<HiveTableNameWithContext, PartitionStatistics>()
                {
                    @Override
                    public PartitionStatistics load(HiveTableNameWithContext key)
                    {
                        return loadTableColumnStatistics(key);
                    }
                }, executor));

        partitionStatisticsCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(new CacheLoader<HivePartitionNameWithContext, PartitionStatistics>()
                {
                    @Override
                    public PartitionStatistics load(HivePartitionNameWithContext key)
                    {
                        return loadPartitionColumnStatistics(key);
                    }

                    @Override
                    public Map<HivePartitionNameWithContext, PartitionStatistics> loadAll(Iterable<? extends HivePartitionNameWithContext> keys)
                    {
                        return loadPartitionColumnStatistics(keys);
                    }
                }, executor));

        tableCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadTable), executor));

        viewNamesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadAllViews), executor));

        partitionNamesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadPartitionNames), executor));

        partitionFilterCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadPartitionNamesByParts), executor));

        partitionCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(new CacheLoader<HivePartitionNameWithContext, Optional<Partition>>()
                {
                    @Override
                    public Optional<Partition> load(HivePartitionNameWithContext partitionName)
                    {
                        return loadPartitionByName(partitionName);
                    }

                    @Override
                    public Map<HivePartitionNameWithContext, Optional<Partition>> loadAll(Iterable<? extends HivePartitionNameWithContext> partitionNames)
                    {
                        return loadPartitionsByNames(partitionNames);
                    }
                }, executor));

        tablePrivilegesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(key -> loadTablePrivileges(key.getDatabase(), key.getTable(), key.getOwner(), key.getPrincipal())), executor));

        rolesCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(() -> loadRoles()), executor));

        roleGrantsCache = newCacheBuilder(expiresAfterWriteMillis, refreshMills, maximumSize)
                .build(asyncReloading(CacheLoader.from(this::loadRoleGrants), executor));
    }

    @Managed
    public void flushCache()
    {
        databaseNamesCache.invalidateAll();
        tableNamesCache.invalidateAll();
        viewNamesCache.invalidateAll();
        partitionNamesCache.invalidateAll();
        databaseCache.invalidateAll();
        tableCache.invalidateAll();
        partitionCache.invalidateAll();
        partitionFilterCache.invalidateAll();
        tablePrivilegesCache.invalidateAll();
        tableStatisticsCache.invalidateAll();
        partitionStatisticsCache.invalidateAll();
        rolesCache.invalidateAll();
    }

    private static <K, V> V get(LoadingCache<K, V> cache, K key)
    {
        try {
            return cache.getUnchecked(key);
        }
        catch (UncheckedExecutionException e) {
            throwIfInstanceOf(e.getCause(), PrestoException.class);
            throw e;
        }
    }

    private static <K, V> Map<K, V> getAll(LoadingCache<K, V> cache, Iterable<K> keys)
    {
        try {
            return cache.getAll(keys);
        }
        catch (ExecutionException | UncheckedExecutionException e) {
            throwIfInstanceOf(e.getCause(), PrestoException.class);
            throwIfUnchecked(e);
            throw new UncheckedExecutionException(e);
        }
    }

    @Override
    public Optional<Database> getDatabase(String databaseName)
    {
        return get(databaseCache, databaseName);
    }

    private Optional<Database> loadDatabase(String databaseName)
    {
        return delegate.getDatabase(databaseName);
    }

    @Override
    public List<String> getAllDatabases()
    {
        return get(databaseNamesCache, "");
    }

    private List<String> loadAllDatabases()
    {
        return delegate.getAllDatabases();
    }

    @Override
    public Optional<Table> getTable(HiveContext context, String databaseName, String tableName)
    {
        return get(tableCache, hiveTableNameWithContext(context, databaseName, tableName));
    }

    @Override
    public Set<ColumnStatisticType> getSupportedColumnStatistics(Type type)
    {
        return delegate.getSupportedColumnStatistics(type);
    }

    private Optional<Table> loadTable(HiveTableNameWithContext hiveTableName)
    {
        return delegate.getTable(hiveTableName.getContext(), hiveTableName.getDatabaseName(), hiveTableName.getTableName());
    }

    @Override
    public PartitionStatistics getTableStatistics(HiveContext context, String databaseName, String tableName)
    {
        return get(tableStatisticsCache, hiveTableNameWithContext(context, databaseName, tableName));
    }

    private PartitionStatistics loadTableColumnStatistics(HiveTableNameWithContext hiveTableName)
    {
        return delegate.getTableStatistics(hiveTableName.getContext(), hiveTableName.getDatabaseName(), hiveTableName.getTableName());
    }

    @Override
    public Map<String, PartitionStatistics> getPartitionStatistics(HiveContext context, String databaseName, String tableName, Set<String> partitionNames)
    {
        List<HivePartitionNameWithContext> partitions = partitionNames.stream()
                .map(partitionName -> HivePartitionNameWithContext.hivePartitionNameWithContext(context, databaseName, tableName, partitionName))
                .collect(toImmutableList());
        Map<HivePartitionNameWithContext, PartitionStatistics> statistics = getAll(partitionStatisticsCache, partitions);
        return statistics.entrySet()
                .stream()
                .collect(toImmutableMap(entry -> entry.getKey().getPartitionName().get(), Entry::getValue));
    }

    private PartitionStatistics loadPartitionColumnStatistics(HivePartitionNameWithContext partition)
    {
        String partitionName = partition.getPartitionName().get();
        Map<String, PartitionStatistics> partitionStatistics = delegate.getPartitionStatistics(
                partition.getHiveTableName().getContext(),
                partition.getHiveTableName().getDatabaseName(),
                partition.getHiveTableName().getTableName(),
                ImmutableSet.of(partitionName));
        if (!partitionStatistics.containsKey(partitionName)) {
            throw new PrestoException(HIVE_PARTITION_DROPPED_DURING_QUERY, "Statistics result does not contain entry for partition: " + partition.getPartitionName());
        }
        return partitionStatistics.get(partitionName);
    }

    private Map<HivePartitionNameWithContext, PartitionStatistics> loadPartitionColumnStatistics(Iterable<? extends HivePartitionNameWithContext> keys)
    {
        SetMultimap<HiveTableNameWithContext, HivePartitionNameWithContext> tablePartitions = stream(keys)
                .collect(toImmutableSetMultimap(HivePartitionNameWithContext::getHiveTableName, key -> key));
        ImmutableMap.Builder<HivePartitionNameWithContext, PartitionStatistics> result = ImmutableMap.builder();
        tablePartitions.keySet().forEach(table -> {
            Set<String> partitionNames = tablePartitions.get(table).stream()
                    .map(partitionName -> partitionName.getPartitionName().get())
                    .collect(toImmutableSet());
            Map<String, PartitionStatistics> partitionStatistics = delegate.getPartitionStatistics(table.getContext(), table.getDatabaseName(), table.getTableName(), partitionNames);
            for (String partitionName : partitionNames) {
                if (!partitionStatistics.containsKey(partitionName)) {
                    throw new PrestoException(HIVE_PARTITION_DROPPED_DURING_QUERY, "Statistics result does not contain entry for partition: " + partitionName);
                }
                result.put(hivePartitionNameWithContext(table, partitionName), partitionStatistics.get(partitionName));
            }
        });
        return result.build();
    }

    @Override
    public void updateTableStatistics(HiveContext context, String databaseName, String tableName, Function<PartitionStatistics, PartitionStatistics> update)
    {
        try {
            delegate.updateTableStatistics(context, databaseName, tableName, update);
        }
        finally {
            tableStatisticsCache.invalidate(hiveTableName(databaseName, tableName));
        }
    }

    @Override
    public void updatePartitionStatistics(HiveContext context, String databaseName, String tableName, String partitionName, Function<PartitionStatistics, PartitionStatistics> update)
    {
        try {
            delegate.updatePartitionStatistics(context, databaseName, tableName, partitionName, update);
        }
        finally {
            partitionStatisticsCache.invalidate(HivePartitionName.hivePartitionName(databaseName, tableName, partitionName));
        }
    }

    @Override
    public List<String> getAllTables(String databaseName)
    {
        return get(tableNamesCache, databaseName);
    }

    private List<String> loadAllTables(String databaseName)
    {
        return delegate.getAllTables(databaseName);
    }

    @Override
    public List<String> getTablesWithParameter(String databaseName, String parameterKey, String parameterValue)
    {
        TablesWithParameterCacheKey key = new TablesWithParameterCacheKey(databaseName, parameterKey, parameterValue);
        return get(tablesWithParameterCache, key);
    }

    private List<String> loadTablesMatchingParameter(TablesWithParameterCacheKey key)
    {
        return delegate.getTablesWithParameter(key.getDatabaseName(), key.getParameterKey(), key.getParameterValue());
    }

    @Override
    public List<String> getAllViews(String databaseName)
    {
        return get(viewNamesCache, databaseName);
    }

    private List<String> loadAllViews(String databaseName)
    {
        return delegate.getAllViews(databaseName);
    }

    @Override
    public void createDatabase(HiveContext context, Database database)
    {
        try {
            delegate.createDatabase(context, database);
        }
        finally {
            invalidateDatabase(database.getDatabaseName());
        }
    }

    @Override
    public void dropDatabase(HiveContext context, String databaseName)
    {
        try {
            delegate.dropDatabase(context, databaseName);
        }
        finally {
            invalidateDatabase(databaseName);
        }
    }

    @Override
    public void renameDatabase(HiveContext context, String databaseName, String newDatabaseName)
    {
        try {
            delegate.renameDatabase(context, databaseName, newDatabaseName);
        }
        finally {
            invalidateDatabase(databaseName);
            invalidateDatabase(newDatabaseName);
        }
    }

    protected void invalidateDatabase(String databaseName)
    {
        databaseCache.invalidate(databaseName);
        databaseNamesCache.invalidateAll();
    }

    @Override
    public void createTable(HiveContext context, Table table, PrincipalPrivileges principalPrivileges)
    {
        try {
            delegate.createTable(context, table, principalPrivileges);
        }
        finally {
            invalidateTable(table.getDatabaseName(), table.getTableName());
        }
    }

    @Override
    public void dropTable(HiveContext context, String databaseName, String tableName, boolean deleteData)
    {
        try {
            delegate.dropTable(context, databaseName, tableName, deleteData);
        }
        finally {
            invalidateTable(databaseName, tableName);
        }
    }

    @Override
    public void replaceTable(HiveContext context, String databaseName, String tableName, Table newTable, PrincipalPrivileges principalPrivileges)
    {
        try {
            delegate.replaceTable(context, databaseName, tableName, newTable, principalPrivileges);
        }
        finally {
            invalidateTable(databaseName, tableName);
            invalidateTable(newTable.getDatabaseName(), newTable.getTableName());
        }
    }

    @Override
    public void renameTable(HiveContext context, String databaseName, String tableName, String newDatabaseName, String newTableName)
    {
        try {
            delegate.renameTable(context, databaseName, tableName, newDatabaseName, newTableName);
        }
        finally {
            invalidateTable(databaseName, tableName);
            invalidateTable(newDatabaseName, newTableName);
        }
    }

    @Override
    public void commentTable(HiveContext context, String databaseName, String tableName, Optional<String> comment)
    {
        try {
            delegate.commentTable(context, databaseName, tableName, comment);
        }
        finally {
            invalidateTable(databaseName, tableName);
        }
    }

    @Override
    public void addColumn(HiveContext context, String databaseName, String tableName, String columnName, HiveType columnType, String columnComment)
    {
        try {
            delegate.addColumn(context, databaseName, tableName, columnName, columnType, columnComment);
        }
        finally {
            invalidateTable(databaseName, tableName);
        }
    }

    @Override
    public void renameColumn(HiveContext context, String databaseName, String tableName, String oldColumnName, String newColumnName)
    {
        try {
            delegate.renameColumn(context, databaseName, tableName, oldColumnName, newColumnName);
        }
        finally {
            invalidateTable(databaseName, tableName);
        }
    }

    @Override
    public void dropColumn(HiveContext context, String databaseName, String tableName, String columnName)
    {
        try {
            delegate.dropColumn(context, databaseName, tableName, columnName);
        }
        finally {
            invalidateTable(databaseName, tableName);
        }
    }

    protected void invalidateTable(String databaseName, String tableName)
    {
        invalidateTableCache(databaseName, tableName);
        tableNamesCache.invalidate(databaseName);
        viewNamesCache.invalidate(databaseName);
        tablePrivilegesCache.asMap().keySet().stream()
                .filter(userTableKey -> userTableKey.matches(databaseName, tableName))
                .forEach(tablePrivilegesCache::invalidate);
        invalidateTableStatisticsCache(databaseName, tableName);
        invalidatePartitionCache(databaseName, tableName);
    }

    private void invalidateTableCache(String databaseName, String tableName)
    {
        tableCache.asMap().keySet().stream()
                .filter(table -> table.getDatabaseName().equals(databaseName) && table.getTableName().equals(tableName))
                .forEach(tableCache::invalidate);
    }

    private void invalidateTableStatisticsCache(String databaseName, String tableName)
    {
        tableStatisticsCache.asMap().keySet().stream()
                .filter(table -> table.getDatabaseName().equals(databaseName) && table.getTableName().equals(tableName))
                .forEach(tableCache::invalidate);
    }

    @Override
    public Optional<Partition> getPartition(HiveContext context, String databaseName, String tableName, List<String> partitionValues)
    {
        HiveTableNameWithContext hiveTableNameWithContext = hiveTableNameWithContext(context, databaseName, tableName);
        HivePartitionNameWithContext name = hivePartitionNameWithContext(hiveTableNameWithContext, partitionValues);
        return get(partitionCache, name);
    }

    @Override
    public Optional<List<String>> getPartitionNames(HiveContext context, String databaseName, String tableName)
    {
        return get(partitionNamesCache, hiveTableNameWithContext(context, databaseName, tableName));
    }

    private Optional<List<String>> loadPartitionNames(HiveTableNameWithContext hiveTableName)
    {
        return delegate.getPartitionNames(hiveTableName.getContext(), hiveTableName.getDatabaseName(), hiveTableName.getTableName());
    }

    @Override
    public Optional<List<String>> getPartitionNamesByParts(HiveContext context, String databaseName, String tableName, List<String> parts)
    {
        return get(partitionFilterCache, partitionFilterWithContext(context, databaseName, tableName, parts));
    }

    private Optional<List<String>> loadPartitionNamesByParts(PartitionFilterWithContext partitionFilter)
    {
        return delegate.getPartitionNamesByParts(
                partitionFilter.getHiveTableName().getContext(),
                partitionFilter.getHiveTableName().getDatabaseName(),
                partitionFilter.getHiveTableName().getTableName(),
                partitionFilter.getParts());
    }

    @Override
    public Map<String, Optional<Partition>> getPartitionsByNames(HiveContext context, String databaseName, String tableName, List<String> partitionNames)
    {
        Iterable<HivePartitionNameWithContext> names = transform(partitionNames, name -> HivePartitionNameWithContext.hivePartitionNameWithContext(context, databaseName, tableName, name));

        Map<HivePartitionNameWithContext, Optional<Partition>> all = getAll(partitionCache, names);
        ImmutableMap.Builder<String, Optional<Partition>> partitionsByName = ImmutableMap.builder();
        for (Entry<HivePartitionNameWithContext, Optional<Partition>> entry : all.entrySet()) {
            partitionsByName.put(entry.getKey().getPartitionName().get(), entry.getValue());
        }
        return partitionsByName.build();
    }

    private Optional<Partition> loadPartitionByName(HivePartitionNameWithContext partitionName)
    {
        return delegate.getPartition(
                partitionName.getHiveTableName().getContext(),
                partitionName.getHiveTableName().getDatabaseName(),
                partitionName.getHiveTableName().getTableName(),
                partitionName.getPartitionValues());
    }

    private Map<HivePartitionNameWithContext, Optional<Partition>> loadPartitionsByNames(Iterable<? extends HivePartitionNameWithContext> partitionNames)
    {
        requireNonNull(partitionNames, "partitionNames is null");
        checkArgument(!Iterables.isEmpty(partitionNames), "partitionNames is empty");

        HivePartitionNameWithContext firstPartition = Iterables.get(partitionNames, 0);

        HiveTableNameWithContext hiveTableName = firstPartition.getHiveTableName();
        HiveContext context = hiveTableName.getContext();
        String databaseName = hiveTableName.getDatabaseName();
        String tableName = hiveTableName.getTableName();

        List<String> partitionsToFetch = new ArrayList<>();
        for (HivePartitionNameWithContext partitionName : partitionNames) {
            checkArgument(partitionName.getHiveTableName().equals(hiveTableName), "Expected table name %s but got %s", hiveTableName, partitionName.getHiveTableName());
            partitionsToFetch.add(partitionName.getPartitionName().get());
        }

        ImmutableMap.Builder<HivePartitionNameWithContext, Optional<Partition>> partitions = ImmutableMap.builder();
        Map<String, Optional<Partition>> partitionsByNames = delegate.getPartitionsByNames(context, databaseName, tableName, partitionsToFetch);
        for (Entry<String, Optional<Partition>> entry : partitionsByNames.entrySet()) {
            partitions.put(hivePartitionNameWithContext(hiveTableName, entry.getKey()), entry.getValue());
        }
        return partitions.build();
    }

    @Override
    public void addPartitions(HiveContext context, String databaseName, String tableName, List<PartitionWithStatistics> partitions)
    {
        try {
            delegate.addPartitions(context, databaseName, tableName, partitions);
        }
        finally {
            // todo do we need to invalidate all partitions?
            invalidatePartitionCache(databaseName, tableName);
        }
    }

    @Override
    public void dropPartition(HiveContext context, String databaseName, String tableName, List<String> parts, boolean deleteData)
    {
        try {
            delegate.dropPartition(context, databaseName, tableName, parts, deleteData);
        }
        finally {
            invalidatePartitionCache(databaseName, tableName);
        }
    }

    @Override
    public void alterPartition(HiveContext context, String databaseName, String tableName, PartitionWithStatistics partition)
    {
        try {
            delegate.alterPartition(context, databaseName, tableName, partition);
        }
        finally {
            invalidatePartitionCache(databaseName, tableName);
        }
    }

    @Override
    public void createRole(HiveContext context, String role, String grantor)
    {
        try {
            delegate.createRole(context, role, grantor);
        }
        finally {
            rolesCache.invalidateAll();
        }
    }

    @Override
    public void dropRole(HiveContext context, String role)
    {
        try {
            delegate.dropRole(context, role);
        }
        finally {
            rolesCache.invalidateAll();
            roleGrantsCache.invalidateAll();
        }
    }

    @Override
    public Set<String> listRoles()
    {
        return get(rolesCache, "");
    }

    private Set<String> loadRoles()
    {
        return delegate.listRoles();
    }

    @Override
    public void grantRoles(HiveContext context, Set<String> roles, Set<HivePrincipal> grantees, boolean withAdminOption, HivePrincipal grantor)
    {
        try {
            delegate.grantRoles(context, roles, grantees, withAdminOption, grantor);
        }
        finally {
            roleGrantsCache.invalidateAll();
        }
    }

    @Override
    public void revokeRoles(HiveContext context, Set<String> roles, Set<HivePrincipal> grantees, boolean adminOptionFor, HivePrincipal grantor)
    {
        try {
            delegate.revokeRoles(context, roles, grantees, adminOptionFor, grantor);
        }
        finally {
            roleGrantsCache.invalidateAll();
        }
    }

    @Override
    public Set<RoleGrant> listRoleGrants(HivePrincipal principal)
    {
        return get(roleGrantsCache, principal);
    }

    private Set<RoleGrant> loadRoleGrants(HivePrincipal principal)
    {
        return delegate.listRoleGrants(principal);
    }

    private void invalidatePartitionCache(String databaseName, String tableName)
    {
        HiveTableName hiveTableName = hiveTableName(databaseName, tableName);
        partitionNamesCache.invalidate(hiveTableName);
        partitionCache.asMap().keySet().stream()
                .filter(partitionName -> partitionName.getHiveTableName().equals(hiveTableName))
                .forEach(partitionCache::invalidate);
        partitionFilterCache.asMap().keySet().stream()
                .filter(partitionFilter -> partitionFilter.getHiveTableName().equals(hiveTableName))
                .forEach(partitionFilterCache::invalidate);
        partitionStatisticsCache.asMap().keySet().stream()
                .filter(partitionFilter -> partitionFilter.getHiveTableName().equals(hiveTableName))
                .forEach(partitionStatisticsCache::invalidate);
    }

    @Override
    public void grantTablePrivileges(HiveContext context, String databaseName, String tableName, String tableOwner, HivePrincipal grantee, Set<HivePrivilegeInfo> privileges)
    {
        try {
            delegate.grantTablePrivileges(context, databaseName, tableName, tableOwner, grantee, privileges);
        }
        finally {
            tablePrivilegesCache.invalidate(new UserTableKey(grantee, databaseName, tableName, tableOwner));
        }
    }

    @Override
    public void revokeTablePrivileges(HiveContext context, String databaseName, String tableName, String tableOwner, HivePrincipal grantee, Set<HivePrivilegeInfo> privileges)
    {
        try {
            delegate.revokeTablePrivileges(context, databaseName, tableName, tableOwner, grantee, privileges);
        }
        finally {
            tablePrivilegesCache.invalidate(new UserTableKey(grantee, databaseName, tableName, tableOwner));
        }
    }

    @Override
    public Set<HivePrivilegeInfo> listTablePrivileges(String databaseName, String tableName, String tableOwner, HivePrincipal principal)
    {
        return get(tablePrivilegesCache, new UserTableKey(principal, databaseName, tableName, tableOwner));
    }

    private Set<HivePrivilegeInfo> loadTablePrivileges(String databaseName, String tableName, String tableOwner, HivePrincipal principal)
    {
        return delegate.listTablePrivileges(databaseName, tableName, tableOwner, principal);
    }

    private static CacheBuilder<Object, Object> newCacheBuilder(OptionalLong expiresAfterWriteMillis, OptionalLong refreshMillis, long maximumSize)
    {
        CacheBuilder<Object, Object> cacheBuilder = CacheBuilder.newBuilder();
        if (expiresAfterWriteMillis.isPresent()) {
            cacheBuilder = cacheBuilder.expireAfterWrite(expiresAfterWriteMillis.getAsLong(), MILLISECONDS);
        }
        if (refreshMillis.isPresent() && (!expiresAfterWriteMillis.isPresent() || expiresAfterWriteMillis.getAsLong() > refreshMillis.getAsLong())) {
            cacheBuilder = cacheBuilder.refreshAfterWrite(refreshMillis.getAsLong(), MILLISECONDS);
        }
        cacheBuilder = cacheBuilder.maximumSize(maximumSize);
        return cacheBuilder;
    }
}
