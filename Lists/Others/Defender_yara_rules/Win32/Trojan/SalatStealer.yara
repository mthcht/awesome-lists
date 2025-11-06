rule Trojan_Win32_SalatStealer_KAT_2147946544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KAT!MTB"
        threat_id = "2147946544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decryptData" ascii //weight: 1
        $x_1_2 = "findLsassProcess" ascii //weight: 1
        $x_1_3 = "shellCommand" ascii //weight: 1
        $x_1_4 = "sendScreen" ascii //weight: 1
        $x_1_5 = "runKeylogger" ascii //weight: 1
        $x_1_6 = "salat/main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NV_2147953702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NV!MTB"
        threat_id = "2147953702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {21 d3 09 eb 84 db 75 06 31 d2 31 db eb 14 e8 16 6f 06 00 8b 04 24 8b 4c 24 04 89 ca 89 c3 8b 44 24 3c 89 5c 24 18 89 54 24 1c 8d 48 30}  //weight: 2, accuracy: High
        $x_1_2 = {ff 74 20 e8 7c 7a 06 00 89 0f 8b 58 08 89 5f 04 89 47 08 8b 59 04 89 5f 0c 8b 5e 2c 89 5f 10 8b 5c 24 18 89 48 08 89 41 04 89 46 2c eb 30 8b 0d 60 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_ASE_2147954201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.ASE!MTB"
        threat_id = "2147954201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 3c 3a 31 ef 8b 6c 24 48 97 88 04 2b 97 8d 45 01 89 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NS_2147954535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NS!MTB"
        threat_id = "2147954535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 70 b8 00 01 f3 50 83 c7 08 ff 96 28 70 b8 00}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 2c 70 b8 00 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NB_2147954601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NB!MTB"
        threat_id = "2147954601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5f 04 8d 84 30 00 e0 b7 00 01 f3 50 83 c7 08 ff 96 28 e0 b7 00 95 8a 07 47}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 30 e0 b7 00 09 c0 74 07 89 03 83 c3 04 eb e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NC_2147954718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NC!MTB"
        threat_id = "2147954718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 00 b8 00 01 f3}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 2c 00 b8 00 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_EI_2147956951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.EI!MTB"
        threat_id = "2147956951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 3d 68 6e f9 00 0f b6 3c 3a 31 ef 8b 6c 24 48 97 88 04 2b 97 8d 45 01 89 f2 39 c2 7e 1d 8b 0d 6c 6e f9 00 0f b6 2c 18 85 c9 74 26 89 44 24 48 89 d6 99 f7 f9 39 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

