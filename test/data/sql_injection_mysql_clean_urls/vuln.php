<html>
    <body>
        <?php
            error_reporting(0);

            $conn = new mysqli("test-service-with-sql-injection-mysql-clean-urls-db", "root", "root", "information_schema");

            $sql = "
                SELECT id, content FROM (
                    SELECT '1' AS id, 'content 1' AS content UNION
                    SELECT '2' AS id, 'content 2' AS content UNION
                    SELECT '3' AS id, 'content 3' AS content UNION
                    SELECT '4' AS id, 'content 4' AS content) t WHERE id = '" . $_GET['id'] . "'";
            $result = $conn->query($sql);
            while($row = $result->fetch_assoc()) {
                echo $row["content"];
            }
            $conn->close();
        ?>
    </body>
</html>
