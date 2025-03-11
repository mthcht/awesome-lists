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

rule Trojan_MacOS_PassSteal_B_2147935647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PassSteal.B!MTB"
        threat_id = "2147935647"
        type = "Trojan"
        platform = "MacOS: "
        family = "PassSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 e9 03 00 aa e9 07 00 f9 e1 03 00 f9 28 00 40 f9 28 01 00 f9 28 04 40 f9 20 05 40 f9 28 05 00 f9 b0 01 00 94 e1 03 40 f9 e9 07 40 f9 28 08 40 f9 20 09 40 f9 28 09 00 f9 ea 00 00 94 e0 07 40 f9 fd 7b 41 a9 ff 83 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {fd 7b bf a9 fd 03 00 91 ff 83 01 d1 a8 03 1c f8 a0 83 1a f8 a1 03 1d f8 a2 83 1d f8 a3 03 1e f8 a4 83 1e f8 e8 03 01 aa a8 83 1f f8 e8 03 02 aa a8 03 1f f8 00 00 80 d2 ed 22 00 94 a2 03 5d f8 a1 83 5a f8 a0 83 1b f8 08 80 5f f8 08 21 40 f9 08 fd 40 d3 08 3d 00 91 09 ed 7c 92 a9 03 1b f8 50 00 00 f0 10 4a 40 f9 00 02 3f d6 a9 03 5b f8 e8 03 00 91 00 01 09 eb a0 83 1c f8 1f 00 00 91 48 80 5f f8 08 09 40 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

