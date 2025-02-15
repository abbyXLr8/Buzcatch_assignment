<?php
    include("connection.php");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
    <div id="logindiv">
        <h1 >Login Page</h1>
        <br>
        <form name = "form" action = "loginlogic.php" method="post">
            <input type="text" id = "user" name = "user" style="border-radius: 5px;" placeholder="Enter Username">
            <br>
            <br>
            <input type="password" id = "pass" name = "pass"  style="border-radius: 5px;" placeholder="Enter Password">
            <br>
            <br>
            <input type="submit" id="subbttn" name="subbttn" value="Login">
        </form>
        <a href="signup.php" style="color: white; text-decoration: none" >sign up</a>
    </div>
</body>
</html>