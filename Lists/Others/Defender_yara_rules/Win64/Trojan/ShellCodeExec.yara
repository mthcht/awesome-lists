rule Trojan_Win64_ShellCodeExec_DA_2147923763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeExec.DA!MTB"
        threat_id = "2147923763"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 8b 8c eb 00 e3 03 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2 7c df}  //weight: 1, accuracy: High
        $x_1_2 = {48 ff c6 48 89 7c 24 38 48 89 7c 24 30 c7 44 24 28 05 00 00 00 48 8d 45 0f 48 89 44 24 20 45 8b cc 4c 8d 45 93 33 d2 8b 4d b7 e8 73 2e 00 00 44 8b f0 85 c0 0f 84 1b 01 00 00 48 89 7c 24 20 4c 8d 4d 97 44 8b c0 48 8d 55 0f 4c 8b 65 e7 49 8b cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCodeExec_DB_2147923764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeExec.DB!MTB"
        threat_id = "2147923764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 49 8b 73 30 49 8b e3 41 5f 41 5e 5f c3 cc f0 ff 41 08 8b 41 08 c3 b8 01 40 00 80 c3 cc cc 4d 85 c0 75 06 b8 03 40 00 80 c3 4c 8b 49 10 49 8b 81 30 08 00 00 48 3b 02 75 0d 49 8b 81 38 08 00 00 48 3b 42 08 74 19 49 8b 81 f0 08 00 00 48 3b 02 75 17 49 8b 81 f8 08 00 00 48 3b 42 08 75 0a 49 89 08 f0 ff 41 08 33 c0 c3 49 83 20 00 b8 02 40 00 80 c3 cc cc cc 83 c8 ff f0 0f c1 41 08 ff c8 c3 cc 33 c0 c3 cc 48 89 5c 24 08}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 60 41 83 ca ff 45 33 c0 48 8b f1 44 38 02 74 19 41 83 f8 40 73 13 41 8a 04 10 42 88 44 04 20 41 ff c0 41 80 3c 10 00 75 e7 41 8d 40 fc 42 c6 44 04 20 00 80 7c 04 20 2e 74 2a 42 c6 44 04 20 2e 41 ff c0 42 c6 44 04 20 64 41 ff c0 42 c6 44 04 20 6c 41 ff c0 41 8d 40 01 42 c6 44 04 20 6c c6 44 04 20 00 65 48 8b 04 25 30 00 00 00 48 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

