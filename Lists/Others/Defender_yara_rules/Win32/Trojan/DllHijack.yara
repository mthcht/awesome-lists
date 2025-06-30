rule Trojan_Win32_DllHijack_DA_2147901326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.DA!MTB"
        threat_id = "2147901326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 84 14 ?? ?? ?? ?? 33 d9 09 94 04 ?? ?? ?? ?? 13 f9 33 94 44 ?? ?? ?? ?? 0f be 0c 14 0b 54 95 ?? 0f c9 36 66 8b 84 82 ?? ?? ?? ?? 8d ac 4d ?? ?? ?? ?? 2b c9 81 d9 ?? ?? ?? ?? 66 89 44 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_DB_2147901327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.DB!MTB"
        threat_id = "2147901327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d0 f7 d8 d3 ea 89 56 ?? 8b d0 c0 e8 ?? 0f b7 0f 66 c1 c0 ?? 05 ?? ?? ?? ?? 58 66 33 cb 66 ff c1 0f b7 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_CCIF_2147909906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.CCIF!MTB"
        threat_id = "2147909906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 31 47 32 d0 8b c1 88 14 31 99 f7 fb 85 d2 75 ?? 33 ff 8b 44 24 ?? 41 3b c8 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_YAB_2147911997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.YAB!MTB"
        threat_id = "2147911997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 73 b0 f0 3c e8 c7 9f 00 00 89 34 24 c7 44 24 04 34 6d 62 47 a3 ?? ?? ?? ?? e8 b2 9f 00 00 89 34 24 c7 44 24 04 c7 7b 3a a4}  //weight: 1, accuracy: Low
        $x_1_2 = "Direct3DCreate8" ascii //weight: 1
        $x_10_3 = {8d 44 7d 00 03 42 24 0f b7 00 8d 44 85 00 03 42 1c 03 28 83 c4 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_HNA_2147925079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.HNA!MTB"
        threat_id = "2147925079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 95 20 ed ff ff fe 00 00 00 81 c2 3b 66 f3 56 69 85 20 ed ff ff fe 00 00 00 2b d0 81 f2 72 62 aa 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_A_2147927936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.A!MTB"
        threat_id = "2147927936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 c7 c6 44 24 3c 74 81 3f 50 45 00 00 0f b7 47 14 89 7c 24 24 89 54 24 38 0f 85 27 ff ff ff 0f b7 7f 06 89 7c 24 20 66 85 ff 0f 84 16 ff ff ff 8b 7c 24 24 89 4c 24 2c 8d 6c 24 38 8d 74 07 18 31 ff 8d b4 26 00 00 00 00 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_BZ_2147944777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.BZ!MTB"
        threat_id = "2147944777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 45 f0 8b d7 50 8d 4d ec e8 ?? ?? ?? ?? 8b 45 e4 83 c7 06 30 45 f0 83 c4 04 30 65 f1 0f b6 45 ea 30 45 f2 0f b6 45 eb 30 45 f3 8b c6 8b 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DllHijack_BJ_2147945056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllHijack.BJ!MTB"
        threat_id = "2147945056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 59 8b 45 08 03 45 fc 0f b6 00 33 45 10 8b 4d 08 03 4d fc 88 01 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

