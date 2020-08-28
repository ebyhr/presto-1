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
package io.prestosql.ranger;

import io.airlift.log.Logger;
import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.PrestoPrincipal;
import io.prestosql.spi.security.Privilege;
import io.prestosql.spi.security.SystemAccessControl;
import io.prestosql.spi.security.SystemSecurityContext;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static io.prestosql.spi.security.AccessDeniedException.denyAddColumn;
import static io.prestosql.spi.security.AccessDeniedException.denyCreateSchema;
import static io.prestosql.spi.security.AccessDeniedException.denyCreateTable;
import static io.prestosql.spi.security.AccessDeniedException.denyCreateView;
import static io.prestosql.spi.security.AccessDeniedException.denyDeleteTable;
import static io.prestosql.spi.security.AccessDeniedException.denyDropSchema;
import static io.prestosql.spi.security.AccessDeniedException.denyDropTable;
import static io.prestosql.spi.security.AccessDeniedException.denyDropView;
import static io.prestosql.spi.security.AccessDeniedException.denyGrantTablePrivilege;
import static io.prestosql.spi.security.AccessDeniedException.denyInsertTable;
import static io.prestosql.spi.security.AccessDeniedException.denyRenameColumn;
import static io.prestosql.spi.security.AccessDeniedException.denyRenameSchema;
import static io.prestosql.spi.security.AccessDeniedException.denyRenameTable;
import static io.prestosql.spi.security.AccessDeniedException.denyRevokeTablePrivilege;
import static io.prestosql.spi.security.AccessDeniedException.denySelectColumns;
import static io.prestosql.spi.security.AccessDeniedException.denySetSystemSessionProperty;
import static io.prestosql.spi.security.AccessDeniedException.denySetUser;
import static io.prestosql.spi.security.AccessDeniedException.denyShowSchemas;
import static io.prestosql.spi.security.AccessDeniedException.denyShowTables;
import static java.util.Comparator.comparing;
import static java.util.Locale.ENGLISH;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

public class RangerSystemAccessControl
        implements SystemAccessControl
{
    private static final Logger log = Logger.get(RangerSystemAccessControl.class);

    private static final Pattern COMPILE = Pattern.compile("@.*");
    private static final Pattern PATTERN = Pattern.compile("/.*");
    private final Set<String> powerPrincipals;
    private final PrestoAuthorizer authorizer;

    public RangerSystemAccessControl(PrestoAuthorizer authorizer, Map<String, String> config)
    {
        this.authorizer = authorizer;

        String[] powerPrincipals = config.getOrDefault("power-principals", "").split(",");
        this.powerPrincipals = Arrays.stream(powerPrincipals)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(ENGLISH)).collect(toSet());
    }

    private static RangerPrestoResource createResource(CatalogSchemaName catalogSchema)
    {
        return createResource(catalogSchema.getCatalogName(), catalogSchema.getSchemaName());
    }

    private static RangerPrestoResource createResource(CatalogSchemaTableName catalogSchema)
    {
        return createResource(catalogSchema.getCatalogName(), catalogSchema.getSchemaTableName().getSchemaName(),
                catalogSchema.getSchemaTableName().getTableName());
    }

    private static RangerPrestoResource createResource(String catalogName)
    {
        return new RangerPrestoResource(catalogName, Optional.empty(), Optional.empty());
    }

    private static RangerPrestoResource createResource(String catalogName, String schemaName)
    {
        return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.empty());
    }

    private static RangerPrestoResource createResource(String catalogName, String schemaName, final String tableName)
    {
        return new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
    }

    private static List<RangerPrestoResource> createResource(CatalogSchemaTableName table, Set<String> columns)
    {
        List<RangerPrestoResource> colRequests = new ArrayList<>();

        if (!columns.isEmpty()) {
            for (String column : columns) {
                RangerPrestoResource rangerPrestoResource = new RangerPrestoResource(table.getCatalogName(),
                        Optional.of(table.getSchemaTableName().getSchemaName()),
                        Optional.of(table.getSchemaTableName().getTableName()), Optional.of(column));
                colRequests.add(rangerPrestoResource);
            }
        }
        else {
            colRequests.add(new RangerPrestoResource(table.getCatalogName(),
                    Optional.of(table.getSchemaTableName().getSchemaName()),
                    Optional.of(table.getSchemaTableName().getTableName()), Optional.empty()));
        }
        return colRequests;
    }

    @Deprecated
    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName)
    {
        // FIXME: This is hack to run anyway
        if (true) {
            return;
        }
        if (principal.isEmpty()) {
            return;
        }
        if (powerPrincipals.contains(principal.get().getName().toLowerCase(ENGLISH))) {
            return;
        }
        String principalName = PATTERN.matcher(COMPILE.matcher(principal.get().getName()).replaceAll("")).replaceAll("");
        if (!principalName.equalsIgnoreCase(userName)) {
            denySetUser(principal, userName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs)
    {
        return catalogs;
    }

    @Override
    public void checkCanExecuteQuery(SystemSecurityContext context)
    {
        log.info("checkCanExecuteQuery");
    }

    @Override
    public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName)
    {
        denySetSystemSessionProperty(propertyName);
    }

    @Override
    public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName)
    {
        denySetSystemSessionProperty(propertyName);
    }

    @Override
    public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        denySetSystemSessionProperty("");
    }

    @Override
    public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor)
    {
        denyRevokeTablePrivilege(table.getCatalogName(), table.getSchemaTableName().getSchemaName(),
                table.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns)
    {
        for (RangerPrestoResource rangerPrestoResource : createResource(table, columns)) {
            if (!authorizer.canSelectResource(rangerPrestoResource, context.getIdentity())) {
                denySelectColumns(table.getSchemaTableName().getTableName(), columns);
            }
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table,
            Set<String> columns)
    {
        for (RangerPrestoResource rangerPrestoResource : createResource(table, columns)) {
            if (!authorizer.canCreateResource(rangerPrestoResource, context.getIdentity())) {
                denySelectColumns(table.getSchemaTableName().getTableName(), columns);
            }
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName catalogSchemaTableName, PrestoPrincipal grantee, boolean withGrantOption)
    {
        denyGrantTablePrivilege(catalogSchemaTableName.getCatalogName(),
                catalogSchemaTableName.getSchemaTableName().getSchemaName(),
                catalogSchemaTableName.getSchemaTableName().getTableName());
    }

    @Override
    public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName)
    {
        // Control by static configuration level because Hive doesn't have catalog
//        if (!authorizer.canSeeResource(createResource(catalogName), context.getIdentity())) {
//            denyCatalogAccess(catalogName);
//        }
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName)
    {
        if (!authorizer.canSeeResource(createResource(catalogName), context.getIdentity())) {
            denyShowSchemas(catalogName);
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName catalogSchemaName)
    {
        if (!authorizer.canSeeResource(createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName()), context.getIdentity())) {
            denyShowTables(catalogSchemaName.getSchemaName());
        }
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames)
    {
        List<RangerPrestoResource> rangerResources = tableNames.stream()
                .map(t -> new RangerPrestoResource(catalogName, Optional.of(t.getSchemaName()),
                        Optional.of(t.getTableName())))
                .collect(toList());

        // TODO: Need to cleanup
        Stream<SchemaTableName> outTables = authorizer.filterResources(rangerResources, context.getIdentity()).stream()
                .map(RangerPrestoResource::getSchemaTable)
                .filter(Optional::isPresent)
                .map(Optional::get);

        return makeSortedSet(outTables, comparing(t -> t.toString().toLowerCase(ENGLISH)));
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames)
    {
        List<RangerPrestoResource> rangerResources = schemaNames.stream()
                .map(schemaName -> new RangerPrestoResource(catalogName, Optional.of(schemaName), Optional.empty()))
                .collect(toList());

        Stream<String> outSchemas = authorizer.filterResources(rangerResources, context.getIdentity()).stream()
                .map(RangerPrestoResource::getDatabase);

        return makeSortedSet(outSchemas, comparing(String::toLowerCase));
    }

    private static <T> SortedSet<T> makeSortedSet(Stream<T> it, Comparator<T> comparator)
    {
        SortedSet<T> set = new TreeSet<>(comparator);
        it.forEach(set::add);
        return set;
    }

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!authorizer.canCreateResource(createResource(schema), context.getIdentity())) {
            denyCreateSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema)
    {
        if (!authorizer.canCreateResource(createResource(schema), context.getIdentity())) {
            denyDropSchema(schema.getSchemaName());
        }
    }

    @Override
    public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName catalogSchema, String newSchemaName)
    {
        if (!authorizer.canCreateResource(createResource(catalogSchema), context.getIdentity()) || !authorizer.canDropResource(
                createResource(catalogSchema.getCatalogName(), catalogSchema.getSchemaName(), newSchemaName),
                context.getIdentity())) {
            denyRenameSchema(catalogSchema.getSchemaName(), newSchemaName);
        }
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canCreateResource(createResource(table), context.getIdentity())) {
            denyCreateTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canDropResource(createResource(table), context.getIdentity())) {
            denyDropTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable)
    {
        if (!authorizer.canCreateResource(createResource(newTable), context.getIdentity()) || !authorizer
                .canDropResource(createResource(table), context.getIdentity())) {
            denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canUpdateResource(createResource(table), context.getIdentity())) {
            denyAddColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canUpdateResource(createResource(table), context.getIdentity())) {
            denyRenameColumn(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canUpdateResource(createResource(table), context.getIdentity())) {
            denyInsertTable(table.getSchemaTableName().getTableName());
        }
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table)
    {
        if (!authorizer.canUpdateResource(createResource(table), context.getIdentity())) {
            denyDeleteTable(table.getSchemaTableName().getTableName());
        }
    }

    public void checkCanCreateView(Identity identity, CatalogSchemaTableName view)
    {
        if (!authorizer.canCreateResource(createResource(view), identity)) {
            denyCreateView(view.getSchemaTableName().getTableName());
        }
    }

    public void checkCanDropView(Identity identity, CatalogSchemaTableName view)
    {
        if (!authorizer.canDropResource(createResource(view), identity)) {
            denyDropView(view.getSchemaTableName().getTableName());
        }
    }
}
