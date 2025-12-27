rule Trojan_Win32_ProcessHijack_PA_2147743874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.PA!MTB"
        threat_id = "2147743874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5b 83 c3 11 93 ba 8f 3f 5d 1a 31 10 83 c0 04 e2 f9}  //weight: 1, accuracy: High
        $x_1_2 = {b9 41 06 00 00 e8 00 00 00 00 5b 83 c3 10 93 81 30 6b af 89 1d 83 c0 04 e2 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessHijack_GTM_2147939658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.GTM!MTB"
        threat_id = "2147939658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c1 8b 45 8c c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 89 54 24 08 89 4c 24 04 89 04 24}  //weight: 5, accuracy: High
        $x_5_2 = {8b 45 e4 8b 48 54 8b 45 08 8b 10 8b 45 e4 8b 40 34 89 c3 8b 45 8c c7 44 24 10 00 00 00 00 89 4c 24 0c 89 54 24 08 89 5c 24 04 89 04 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessHijack_AHB_2147948855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.AHB!MTB"
        threat_id = "2147948855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {58 83 c0 10 ba d4 17 4b 1d 31 10 83 c0 04 e2 f9}  //weight: 10, accuracy: High
        $x_5_2 = {0a d8 2e 9f 5f 08 28 2c 3e 4b a8 ad 0e 77}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ProcessHijack_RI_2147958070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessHijack.RI!MTB"
        threat_id = "2147958070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 f0 8b 40 04 89 45 e4 8b 45 f0 8b 00 89 45 e0 8b 45 ec 89 45 d8 8b 45 f0 83 c0 08 89 45 d4 8b 45 e8 89 45 d0 ff 15 ?? ?? ?? ?? 8b 55 d0 8b 4d d4 89 c3 8b 45 d8 8d 7d e0 8d 75 e4 89 1c 24 89 7c 24 04 89 74 24 08 89 54 24 0c 89 4c 24 10 ff}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 45 f8 3b 45 0c 73 ?? 0f be 75 10 8b 45 08 8b 4d f8 0f be 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 55 08 8b 45 e4 03 50 0c 8b 4d 0c 8b 45 e4 03 48 0c 8b 45 e4 8b 40 08 89 14 24 89 4c 24 04 89 44 24 08 e8 ?? ?? ?? ?? 8b 4d f4 8b 45 e4 8b 50 08 8b 75 08 8b 45 e4 03 70 0c 8d 45 f4 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = "obfuscated_shellcoderunner.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

