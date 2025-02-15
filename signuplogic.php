<?php
    include("connection.php");
    echo("outside isset");
    if(isset($_POST['subbttn'])){
        echo('inside isset');
        $username = $_POST['email'];
        $password = $_POST['pass'];
        $phone = $_POST['phone'];
        echo("variable done");

        $sql = "insert into logindetails(Email,Password,Phone) values('$username','$password','$phone')";
        $result = mysqli_query($conn, $sql);
        if($result){
            echo '<script>
                alert("account created");
                window.location.href = "login.php";
            </script>';
        }
    }
?>