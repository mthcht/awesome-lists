rule Trojan_Win32_Redlinestealer_RW_2147811793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.RW!MTB"
        threat_id = "2147811793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b4 21 e1 c5 c7 [0-5] ff ff ff ff 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8b 4c 24 ?? 81 c7 47 86 c8 61 83 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_UC_2147824748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.UC!MTB"
        threat_id = "2147824748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 ?? 88 10 e9 31 00 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_UD_2147824776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.UD!MTB"
        threat_id = "2147824776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 33 d2 b9 ?? ?? ?? ?? f7 f1 a1 ?? ?? ?? ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_UI_2147825492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.UI!MTB"
        threat_id = "2147825492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 1e 43 eb 37 00 56 53 31 db 83 ec ?? 8b 75 ?? 3b 5d ?? ?? ?? 8d 4d ?? e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_UJ_2147825929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.UJ!MTB"
        threat_id = "2147825929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 03 c7 8a 10 8a ca 80 f1 ?? 88 08 5f 3a ca 74 ?? ff 15 ?? ?? ?? ?? c9 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_UL_2147826121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.UL!MTB"
        threat_id = "2147826121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 8b 45 ?? ba ?? ?? ?? ?? f7 75 ?? 8b 45 ?? 01 d0 0f b6 00 83 f0 ?? 89 c3 8b 55 ?? 8b 45 ?? 01 d0 31 d9 89 ca 88 10 83 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_AMCD_2147898392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.AMCD!MTB"
        threat_id = "2147898392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 f8 06 0f b6 4d db c1 e1 02 0b c1 88 45 db 0f b6 55 db f7 da 88 55 db 0f b6 45 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_AMBE_2147899379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.AMBE!MTB"
        threat_id = "2147899379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 45 db 0f b6 4d db f7 d9 88 4d db 0f b6 55 db c1 fa 07 0f b6 45 db d1 e0 0b d0 88 55 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Redlinestealer_AMBA_2147900733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redlinestealer.AMBA!MTB"
        threat_id = "2147900733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redlinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 30 04 31 83 bc 24 ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

