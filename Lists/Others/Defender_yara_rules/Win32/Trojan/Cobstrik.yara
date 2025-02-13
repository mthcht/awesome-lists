rule Trojan_Win32_Cobstrik_DEA_2147758344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobstrik.DEA!MTB"
        threat_id = "2147758344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobstrik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 b8 23 19 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb 00 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cobstrik_DEB_2147758349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobstrik.DEB!MTB"
        threat_id = "2147758349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobstrik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 b8 25 d5 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb 00 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

