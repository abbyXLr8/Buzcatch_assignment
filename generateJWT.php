<?php

function generateJWT($user_id) {
    $secret_key = "your_secret_key"; // Replace with a strong secret key

    // Header
    $header = json_encode(["alg" => "HS256", "typ" => "JWT"]);
    $header = base64_encode($header);

    // Payload
    $payload = json_encode([
        "user_id" => $user_id,
        "exp" => time() + (60 * 60), // 1 hour expiration
        "iat" => time()
    ]);
    $payload = base64_encode($payload);

    // Signature
    $signature = hash_hmac("sha256", "$header.$payload", $secret_key, true);
    $signature = base64_encode($signature);

    return "$header.$payload.$signature";
}

function validateJWT($jwt) {
    $secret_key = "your_secret_key"; // Must match the one in generateJWT()

    // Split JWT into three parts
    $parts = explode(".", $jwt);
    if (count($parts) !== 3) {
        return false; // Invalid JWT format
    }

    list($header, $payload, $signature) = $parts;

    // Verify signature
    $expected_signature = base64_encode(hash_hmac("sha256", "$header.$payload", $secret_key, true));
    if ($signature !== $expected_signature) {
        return false; // Invalid signature
    }

    // Decode payload
    $decoded_payload = json_decode(base64_decode($payload), true);

    // Check expiration time
    if ($decoded_payload["exp"] < time()) {
        return false; // Token expired
    }

    return $decoded_payload; // Return decoded data if valid
}


// Example usage
//session_start();
session_start();
echo $_SESSION['username'] . '<br>';
$token = generateJWT($_SESSION['username']);
echo $token;
?>

<?php
function authenticate() {
    $headers = getallheaders(); // Get all request headers

    // Check if 'Authorization' header is present
    if (!isset($headers['Authorization'])) {
        http_response_code(401); // Unauthorized
        echo json_encode(["error" => "Unauthorized: No token provided"]);
        exit();
    }

    // Extract the token from "Bearer <token>"
    $token = str_replace("Bearer ", "", $headers['Authorization']);
    
    // Validate the token
    $decoded = validateJWT($token);
    if (!$decoded) {
        http_response_code(401); // Unauthorized
        echo json_encode(["error" => "Invalid or expired token"]);
        exit();
    }

    return $decoded; // Return decoded user data
}
?>