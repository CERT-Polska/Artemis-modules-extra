<html>
    <body>
        <div>
            <pre>document.writeln(new URL(window.location.href).searchParams.get("a"))</pre>
            <script>document.writeln(new URL(window.location.href).searchParams.get("a"))</script>
        </div>
        <div>
            <pre>document.write(new URLSearchParams(window.location.search).get("b"))</pre>
            <script>document.write(new URLSearchParams(window.location.search).get("b"))</script>
        </div>
        <div>
            <pre>eval(new URLSearchParams(window.location.search).get("c") || "")</pre>
            <script>eval(new URLSearchParams(window.location.search).get("c") || "")</script>
        </div>
        <div>
            <div id="xss-d"></div>
            <pre>document.querySelector("#xss-d").innerHTML = new URLSearchParams(window.location.search).get("d")</pre>
            <script>document.querySelector("#xss-d").innerHTML = new URLSearchParams(window.location.search).get("d")</script>
        </div>
    </body>
</html>

