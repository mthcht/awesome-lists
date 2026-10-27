rule Trojan_Win64_ShellRunner_JL_2147838047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellRunner.JL!MTB"
        threat_id = "2147838047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellcode.dll" ascii //weight: 1
        $x_1_2 = "Failed to load shellcode.dll" ascii //weight: 1
        $x_1_3 = "RunThatShit" ascii //weight: 1
        $x_1_4 = {00 02 00 00 d0 14 00 00 00 10 00 00 00 00 00 40 01 00 00 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellRunner_DA_2147979529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellRunner.DA!MTB"
        threat_id = "2147979529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 c2 ff c2 6b c8 11 80 f1 5a 41 88 08 49 ff c0 81 fa 00 02 00 00 7c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellRunner_DB_2147980999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellRunner.DB!MTB"
        threat_id = "2147980999"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 2c e5 c3 22 4d 8b 90 22 4d 8b 90 22 4d 8b 90 2b 35 18 90 28 4d 8b 90 70 25 8e 91 33 4d 8b 90 70 25 8f 91 2a 4d 8b 90 70 25 88 91 20 4d 8b 90 8c 24 8a 91 20 4d 8b 90 70 25 8a 91 26 4d 8b 90 5b cc 8f 91 20 4d 8b 90 5b cc 8a 91 2d 4d 8b 90 22 4d 8a 90 44 4d 8b 90 8c 24 82 91 23 4d 8b 90 8c 24 8b 91 23 4d 8b 90 8c 24 74 90 23 4d 8b 90 8c 24 89 91 23 4d 8b 90 52 69 63 68 22 4d 8b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

