rule Trojan_MacOS_PassSteal_A_2147850517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PassSteal.A"
        threat_id = "2147850517"
        type = "Trojan"
        platform = "MacOS: "
        family = "PassSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "data_stealers.rsSELECT origin_url, username_value, password_value FROM logins;" ascii //weight: 1
        $x_1_2 = {66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 66 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 70 72 6f 63 65 73 73 73 72 63 2f 62 72 6f 77 73 65 72 73 2f [0-16] 2f 6d 6f 64 75 6c 65 73 2f 6b 65 79 5f 73 74 65 61 6c}  //weight: 1, accuracy: Low
        $x_1_3 = ".dbSELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies;" ascii //weight: 1
        $x_1_4 = "firefox..modules..data_stealers..DataStealer$GT$13get_passwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_PassSteal_AB_2147897379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PassSteal.AB"
        threat_id = "2147897379"
        type = "Trojan"
        platform = "MacOS: "
        family = "PassSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 [0-160] 50 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64}  //weight: 2, accuracy: Low
        $x_1_2 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'" ascii //weight: 1
        $x_1_3 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 46 69 72 65 66 6f 78 2f 50 72 6f 66 69 6c 65 73 2f [0-160] 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65}  //weight: 1, accuracy: Low
        $x_1_4 = "dscl /Local/Default -authonly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_PassSteal_A_2147920007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PassSteal.A!MTB"
        threat_id = "2147920007"
        type = "Trojan"
        platform = "MacOS: "
        family = "PassSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 9d 16 00 00 48 83 c4 30 0f 0b 48 8b 85 50 ff ff ff 48 89 45 c8 31 c0 89 c7 e8 f3 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 83 ff 00 0f 9c c0 a8 01 75 ?? 48 8b 4d f8 31 c0 48 39 c8 7c ?? 48 8b 3d 8f 4d 00 00 e8 ea 34 00 00 48 8b 05 83 4d 00 00 48 89 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

