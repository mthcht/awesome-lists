rule Trojan_Win32_ReLineStealer_XV_2147820141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReLineStealer.XV!MTB"
        threat_id = "2147820141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 53 31 db 83 ec ?? 8b 7d ?? 3b 5d ?? ?? ?? 89 d8 31 d2 8d 4d ?? f7 75 ?? 8b 45 ?? 0f be 34 10 e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

