rule Trojan_Win32_Bandra_BA_2147821775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.BA!MTB"
        threat_id = "2147821775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 83 f2 01 0f af d0 8b 45 f4 c1 ea 08 32 14 30 88 55 fc e8 [0-4] 8b 55 f4 ff 45 f4 8a 45 fc 88 04 32 39 5d f4 72}  //weight: 1, accuracy: Low
        $x_1_2 = "koyu.space/@ronxik123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_EM_2147834104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.EM!MTB"
        threat_id = "2147834104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 7e 07 00 00 72 e6}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_CB_2147836033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.CB!MTB"
        threat_id = "2147836033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ioc.exchange/@tiagoa26" ascii //weight: 1
        $x_1_2 = "Bitcoin\\wallets" ascii //weight: 1
        $x_1_3 = "Downloads\\%s_%s.txt" ascii //weight: 1
        $x_1_4 = "CC\\%s_%s.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_GAB_2147836334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.GAB!MTB"
        threat_id = "2147836334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 33 d2 8b c7 f7 f1 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 04 02 32 04 31 88 06 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_GBQ_2147837122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.GBQ!MTB"
        threat_id = "2147837122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1c 2e 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 8b c8 31 d2 8b c6 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 04 2e 46 3b f7 72}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c8 33 d2 8b c6 83 c4 04 f7 f1 8a 82 ?? ?? ?? ?? 32 c3 88 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Bandra_RPV_2147837483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.RPV!MTB"
        threat_id = "2147837483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c5 f7 f1 8b 44 24 1c 8b 4c 24 18 56 56 8a 04 02 32 04 19 88 03 ff d7 8b 5c 24 10 45 3b 6c 24 20 72 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_GBY_2147837676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.GBY!MTB"
        threat_id = "2147837676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 8b 00 89 45 f4 69 45 f4 ?? ?? ?? ?? 89 45 f4 8b 45 f4 c1 e8 18 33 45 f4 89 45 f4 69 45 f4 ?? ?? ?? ?? 89 45 f4 69 45 fc ?? ?? ?? ?? 89 45 fc 8b 45 fc 33 45 f4 89 45 fc 8b 45 ec 83 c0 04 89 45 ec 8b 45 0c 83 e8 04 89 45 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_RB_2147838874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.RB!MTB"
        threat_id = "2147838874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c7 0f b6 f7 8a 1c 06 02 d3 88 55 0b 0f b6 d2 0f b6 0c 02 88 0c 06 88 1c 02 0f b6 0c 06 0f b6 d3 03 d1 0f b6 ca 8b 55 fc 0f b6 0c 01 30 0c 17 47 8a 55 0b 3b 7d f8 72 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_BAN_2147839177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.BAN!MTB"
        threat_id = "2147839177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 f8 8b 45 fc 33 d2 b9 18 00 00 00 f7 f1 52 8b 4d 08 e8 [0-4] 0f be 10 8b 45 f8 0f b6 08 33 ca 8b 55 f8 88 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_EC_2147841686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.EC!MTB"
        threat_id = "2147841686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {89 84 95 10 f8 ff ff b9 04 00 00 00 6b d1 00 8b 45 fc 8b 4c 15 e8 89 8c 85 40 f0 ff ff ba 04 00 00 00 c1 e2 00 b8 04 00 00 00 6b c8 00 8b 54 15 f0 89 54 0d f0}  //weight: 6, accuracy: High
        $x_1_2 = "vs_community.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_GFM_2147842194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.GFM!MTB"
        threat_id = "2147842194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 14 4e 13 66 c7 45 fc ?? ?? 8a 45 d4 30 44 0d d5 41 83 f9 28 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_RPQ_2147846286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.RPQ!MTB"
        threat_id = "2147846286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 99 f7 7d f0 0f b6 84 15 e8 fe ff ff 8b 4d 10 03 4d ec 0f b6 09 33 c8 8b 45 10 03 45 ec 88 08 8b 45 ec 40 89 45 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bandra_RPX_2147848812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bandra.RPX!MTB"
        threat_id = "2147848812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 89 4c 24 28 8b 31 03 f2 8a 16 46 88 54 24 0f 84 d2 8b 50 18}  //weight: 1, accuracy: High
        $x_1_2 = "194.169.175.128" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

