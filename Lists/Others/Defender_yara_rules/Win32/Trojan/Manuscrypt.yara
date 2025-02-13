rule Trojan_Win32_Manuscrypt_RPP_2147819404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.RPP!MTB"
        threat_id = "2147819404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 3c 00 00 00 c7 44 24 08 40 04 00 00 c7 44 24 18 ?? ?? ?? ?? c7 44 24 20 01 00 00 00 89 74 24 14 66 c7 44 24 40 72 00 66 c7 44 24 42 75 00 66 c7 44 24 44 6e 00 66 c7 44 24 46 61 00 66 c7 44 24 48 73 00 66 c7 44 24 4a 00 00 ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = "ShellExecuteEx" ascii //weight: 1
        $x_1_3 = "CreateDialogIndirectParam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_RC_2147834147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.RC!MTB"
        threat_id = "2147834147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 00 2e 00 c7 44 24 ?? 7a 00 67 00 [0-32] c7 44 24 ?? 2f 00 25 00 c7 44 24 ?? 64 00 2e 00 c7 ?? 24 [0-4] 6d 00 6c 00 c7 44 24 ?? 74 00 70 00 c7 44 24 ?? 73 00 3a 00 c7 44 24 ?? 2f 00 2f 00 c7 44 24 ?? 76 00 2e 00 c7 44 24 ?? 7a 00 67 00 [0-32] c7 44 24 ?? 2f 00 6c 00 c7 44 24 ?? 6f 00 67 00 c7 44 24 ?? 6f 00 2e 00 c7 44 24 ?? 70 00 6e 00 c7 44 24 ?? 67 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_NEAA_2147836977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.NEAA!MTB"
        threat_id = "2147836977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {51 8d 4d e4 e8 77 08 00 00 8b d0 c6 45 fc 01 83 ec 10 0f 10 45 98 8b 75 f0 8b cc 8b 3e 0f 11 01 8b cb}  //weight: 10, accuracy: High
        $x_5_2 = "vncviewer" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_RPN_2147837174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.RPN!MTB"
        threat_id = "2147837174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 fc c6 45 f4 53 c6 45 f5 48 c6 45 f6 45 c6 45 f7 4c c6 45 f8 4c c6 45 f9 33 c6 45 fa 32 c6 45 fb 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c4 43 c6 45 c5 6f c6 45 c6 43 c6 45 c7 72 c6 45 c8 65 c6 45 c9 61 c6 45 ca 74 c6 45 cb 65 c6 45 cc 49 c6 45 cd 6e c6 45 ce 73 c6 45 cf 74 c6 45 d0 61 c6 45 d1 6e c6 45 d2 63 c6 45 d3 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_GBY_2147837723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.GBY!MTB"
        threat_id = "2147837723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 66 89 85 f0 fd ff ff 0f 1f 44 00 00 8b 8d ?? ?? ?? ?? 03 c8 66 31 8c 45 ?? ?? ?? ?? 40 83 f8 19 72}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_RJ_2147838183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.RJ!MTB"
        threat_id = "2147838183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 00 76 00 c7 44 24 ?? 2e 00 79 00 c7 44 24 ?? 78 00 7a 00 c7 44 24 ?? 67 00 61 00 c7 44 24 ?? 6d 00 65 00 c7 44 24 ?? 6e 00 2e 00 c7 44 24 ?? 63 00 6f 00 c7 44 24 ?? 6d 00 2f 00 c7 44 24 ?? 25 00 64 00 c7 44 24 ?? 2e 00 68 00 c7 44 24 ?? 74 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_RF_2147840828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.RF!MTB"
        threat_id = "2147840828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 6d 00 2f 00 bb 78 00 7a 00 be 6d 00 65 00 [0-96] c7 44 24 ?? 78 00 76 00 c7 44 24 ?? 2e 00 79 00 89 7c 24 ?? 89 54 24 ?? 89 4c 24 ?? c7 44 24 ?? 25 00 64 00 c7 44 24 ?? 2e 00 68 00 c7 44 24 ?? 74 00 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Manuscrypt_AMC_2147848510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Manuscrypt.AMC!MTB"
        threat_id = "2147848510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Manuscrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 80 04 00 8b 07 09 c0 74 45 8b 5f 04 8d 84 30 b8 c1 04 00 01 f3 50 83 c7 08 ff 96 b8 c2 04 00 95 8a 07 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

