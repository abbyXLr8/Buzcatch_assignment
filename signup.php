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
        <form name = "form" action = "signuplogic.php" method="post">
            <input type="text" id = "email" name = "email" style="border-radius: 5px;" placeholder="Enter Email">
            <br>
            <br>
            <input type="password" id = "pass" name = "pass"  style="border-radius: 5px;" placeholder="Enter Password">
            <br>
            <br>
            <input type="text" id = "phone" name = "phone"  style="border-radius: 5px;" placeholder="Enter Phone number">
            <br>
            <br>
            <input type="submit" id="subbttn" name="subbttn" value="Create Account">
        </form>
    </div>
</body>
</html>