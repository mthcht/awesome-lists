rule Trojan_Win32_Morphisil_PM_2147787337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Morphisil.PM!MTB"
        threat_id = "2147787337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Morphisil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e0 30 00 00 8b 45 ?? 03 45 ?? c6 00 00 8b 4d ?? 03 4d ?? 0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 8d 54 11 ?? 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 ea 0e 8b 45 ?? 03 45 ?? 88 10 c7 45 ?? 01 00 00 00 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

