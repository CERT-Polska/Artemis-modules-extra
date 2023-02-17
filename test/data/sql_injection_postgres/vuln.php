<html>
    <body>
        <?php
            error_reporting(0);

            $conn = pg_connect("host=test-service-with-sql-injection-postgres-db user=root password=root");

            $sql = "
                SELECT id, content FROM (
                    SELECT '1' AS id, 'content 1' AS content UNION
                    SELECT '2' AS id, 'content 2' AS content UNION
                    SELECT '3' AS id, 'content 3' AS content UNION
                    SELECT '4' AS id, 'content 4' AS content) t WHERE id = '" . $_GET['id'] . "'";
            $result = pg_query($sql);
            while($row = pg_fetch_array($result, null, PGSQL_ASSOC)) {
                echo $row["content"];
            }

            pg_free_result($result);
            pg_close($conn);
        ?>
    </body>
</html>
