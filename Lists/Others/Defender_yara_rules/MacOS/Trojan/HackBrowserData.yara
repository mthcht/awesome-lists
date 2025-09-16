rule Trojan_MacOS_HackBrowserData_A_2147952327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HackBrowserData.A"
        threat_id = "2147952327"
        type = "Trojan"
        platform = "MacOS: "
        family = "HackBrowserData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, is_secure, is_httponly, has_expires, is_persistent FROM cookies" ascii //weight: 1
        $x_1_2 = {53 45 4c 45 43 54 20 [0-16] 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 2c 20 64 61 74 65 5f 63 72 65 61 74 65 64 20 46 52 4f 4d 20 6c 6f 67 69 6e 73}  //weight: 1, accuracy: Low
        $x_1_3 = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id, nickname FROM credit_cards" ascii //weight: 1
        $x_1_4 = "SELECT name, value, host, path, creationTime, expiry, isSecure, isHttpOnly FROM moz_cookiestable" ascii //weight: 1
        $x_1_5 = "SELECT a11, a102 from nssPrivate" ascii //weight: 1
        $x_1_6 = "SELECT item1, item2 FROM metaData WHERE id = 'password'" ascii //weight: 1
        $x_1_7 = "verification failed: password-check" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

