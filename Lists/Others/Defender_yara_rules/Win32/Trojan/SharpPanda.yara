rule Trojan_Win32_SharpPanda_PA_2147843540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SharpPanda.PA!MTB"
        threat_id = "2147843540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SharpPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 8a 04 1f 88 04 1e 88 0c 1f 0f b6 04 1e 8b 4d ?? 03 c2 8b 55 ?? 0f b6 c0 8a 04 18 30 04 11 41 89 4d ?? 3b 4d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

