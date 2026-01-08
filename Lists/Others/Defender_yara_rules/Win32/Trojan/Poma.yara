rule Trojan_Win32_Poma_SD_2147960810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poma.SD!MTB"
        threat_id = "2147960810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 30 01 8d 04 0b 3b c7 7d ?? 8a 42 ?? 83 c2 ?? 30 41 ?? 83 c1 ?? 8b 45 ?? 03 c2 83 f8 ?? 7c ?? 8b 45 ?? 8b 5d ?? 83 c0 ?? ff 45 ?? 83 45 ?? ?? 3b c7 8b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

