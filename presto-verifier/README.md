# Presto Verifier

The Presto Verifier can be used to test Presto against a database, such
as MySQL, or to test two Presto clusters against each other. We use it
to continuously test the master branch against the previous release,
while developing Presto.

To use the Verifier, create a MySQL database with the following table
and load it with the queries you would like to run:

```sql
CREATE TABLE verifier_queries(
    id INT NOT NULL AUTO_INCREMENT,
    suite VARCHAR(256) NOT NULL,
    name VARCHAR(256),
    test_catalog VARCHAR(256) NOT NULL,
    test_schema VARCHAR(256) NOT NULL,
    test_prequeries TEXT,
    test_query TEXT NOT NULL,
    test_postqueries TEXT,
    test_username VARCHAR(256) NOT NULL default 'verifier-test',
    test_password VARCHAR(256),
    control_catalog VARCHAR(256) NOT NULL,
    control_schema VARCHAR(256) NOT NULL,
    control_prequeries TEXT,
    control_query TEXT NOT NULL,
    control_postqueries TEXT,
    control_username VARCHAR(256) NOT NULL default 'verifier-test',
    control_password VARCHAR(256),
    session_properties_json VARCHAR(2048),
    PRIMARY KEY (id)
);
```

Next, create a properties file to configure the verifier:

```
suite=my_suite
query-database=jdbc:mysql://localhost:3306/my_database?user=my_username&password=my_password
control.gateway=jdbc:presto://localhost:8080
test.gateway=jdbc:presto://localhost:8081
thread-count=1
```

Lastly, download the [Maven verifier plugin][maven_download] for the same 
release as your Presto instance by navigating to the directory for that 
release, and selecting the ``presto-verifier-*.jar`` file. Once it is downloaded, 
rename it to `verifier`, make it executable with `chmod +x`, then run it:

[maven_download]: https://repo.maven.apache.org/maven2/io/prestosql/presto-verifier/

```
./verifier config.properties
```