rule Trojan_Win32_VecStealer_LK_2147845139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VecStealer.LK!MTB"
        threat_id = "2147845139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VecStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 0c 00 00 00 f7 f9 8b 45 ?? 0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

