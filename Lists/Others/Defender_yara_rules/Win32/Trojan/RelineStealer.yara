rule Trojan_Win32_Relinestealer_FA_2147817968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relinestealer.FA!MTB"
        threat_id = "2147817968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 24 4d 00 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 f8 88 10 e9 ?? ?? ?? ?? 83 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {34 24 4d 00 a1 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a1 34 24 4d 00 8b 0d ?? ?? ?? ?? 8a 91}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relinestealer_XG_2147821262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relinestealer.XG!MTB"
        threat_id = "2147821262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 59 bf 88 9d ?? ?? ?? ?? 80 bd ?? ?? ?? ?? ?? 0f be d9 89 9d ?? ?? ?? ?? ?? ?? 83 c9 ?? 0f be c9 89 8d ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 33 9d ?? ?? ?? ?? 69 db ?? ?? ?? ?? 89 9d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Relinestealer_UH_2147825480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relinestealer.UH!MTB"
        threat_id = "2147825480"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relinestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 1e 43}  //weight: 10, accuracy: Low
        $x_10_2 = {0f be d9 77 ?? 83 c9 ?? 0f be d9 31 fb 69 fb ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

