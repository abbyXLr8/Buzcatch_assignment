<?php
    include("connection.php");
    echo("outside isset");
    if(isset($_POST['subbttn'])){
        echo('inside isset');
        $username = $_POST['user'];
        $password = $_POST['pass'];
        echo("variable done");

        $sql = "select * from logindetails where Email = '$username' and Password = '$password'";
        $result = mysqli_query($conn, $sql);
        $row = mysqli_fetch_array($result, MYSQLI_ASSOC);
        $count = mysqli_num_rows($result);
        if($count == 1){
            header("Location:welcome.php");
        }
        else{
            echo '<script>
                window.location.href = "login.php";
                alert("Login failed. Invalid script or password");
            </script>';
        }
    }
?>