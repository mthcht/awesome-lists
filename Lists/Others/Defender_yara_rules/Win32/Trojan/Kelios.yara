rule Trojan_Win32_Kelios_GZZ_2147906982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GZZ!MTB"
        threat_id = "2147906982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 da 66 0f ba e0 14 66 81 fd d7 7a 88 0c 14 66 ff c8 8b 44 25 00}  //weight: 5, accuracy: High
        $x_5_2 = {80 f1 91 fe c9 f5 d0 c9 32 d9 66 89 14 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GZX_2147907199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GZX!MTB"
        threat_id = "2147907199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 40 9c 6c 1c b6 34 f6 bc ?? ?? ?? ?? 5c 70 ea 31 06 64 e5 a5 56}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d4 66 2b d5 0f b7 d1 0f b6 16 66 a9 9a 2e 66 85 ce 8d b6 01 00 00 00 32 d3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GNX_2147918293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GNX!MTB"
        threat_id = "2147918293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 cb 68 02 ?? ?? ?? d0 c1 fe c1 d0 c9 c1 34 24 ?? 80 d1 ?? f6 d1 32 d9 c0 64 24 ?? 22 81 ed ?? ?? ?? ?? 66 89 4c 25 ?? f6 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_CCJU_2147933419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.CCJU!MTB"
        threat_id = "2147933419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 9c bb 83 b3 8b 2c e8 be 70 fd ff 8b ca d3 f1 89 84 17 a9 9f c0 e0 ff e6}  //weight: 2, accuracy: High
        $x_1_2 = {b5 ad 08 77 78 36 97 32 82 ba 8a 5c 9d b1 45 89 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GMX_2147934022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GMX!MTB"
        threat_id = "2147934022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 57 ff c1 48 89 6c 34 ?? 49 c1 ff ?? 42 31 8c fc ?? ?? ?? ?? 5f 48 33 d2 44 8b ea 5d 45 8b c7 4a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GDX_2147934046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GDX!MTB"
        threat_id = "2147934046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f c0 e0 f6 d8 32 cb c1 e8 ?? fe c9 f6 d1 0f b6 d0 80 e9 ?? 80 f1 ?? c1 f8 ?? 89 44 54 ?? 32 d9 58 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GTR_2147936002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GTR!MTB"
        threat_id = "2147936002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 0f be f5 66 d3 ed c0 f1 81 44 31 a4 0c ?? ?? ?? ?? 4c 8d 84 75 ?? ?? ?? ?? 49 81 e0 ?? ?? ?? ?? 5f 4d 63 e4 40 0f b6 d6}  //weight: 10, accuracy: Low
        $x_10_2 = {33 da 41 66 f7 d0 ff 0c 24 03 ea 66 d3 f8 66 33 44 24 ?? 29 4c 24 ?? 58 58 5a 59}  //weight: 10, accuracy: Low
        $x_10_3 = {66 f7 d2 c1 ea ?? 66 33 d2 8a 8c 15 ?? ?? ?? ?? 36 88 8c 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kelios_MCG_2147951845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.MCG!MTB"
        threat_id = "2147951845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 74 76 6d 70 30 00 00 4a b9 58 00 00 e0 4e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 74 76 6d 70 31 00 00 90 00 00 00 00 a0 a7 00 00 10 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 74 76 6d 70 32 00 00 10 03 d2 00 00 b0 a7}  //weight: 1, accuracy: High
        $x_1_2 = {ce 6c ff ff ff b8 9a 1a 9f 11 59 58 e9 5d 2b c7 00 b8 38 3f bc 28 8d 14 45 97 4d 96 ae 8b 8c 06}  //weight: 1, accuracy: High
        $x_1_3 = {2e 72 65 6c 6f 63 00 00 a0 06 00 00 00 e0 79 01 00 10 00 00 00 50 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelios_GSY_2147952061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelios.GSY!MTB"
        threat_id = "2147952061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelios"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 d2 03 c2 f7 d9 33 d9 03 f9 ff 04 24 66 c1 44 24 ?? cc 66 8b 46 ?? c0 7c 24}  //weight: 5, accuracy: Low
        $x_5_2 = {32 c3 c0 c2 ?? fe c8 66 81 c2 ?? ?? 0f c0 f2 81 ea ?? ?? ?? ?? d0 c8 fe c8 f7 d2 fe 8c 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

