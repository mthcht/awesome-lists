rule Trojan_Win32_LummStealer_MAG_2147906592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummStealer.MAG!MTB"
        threat_id = "2147906592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 4d ?? 8b c6 8b 55 fc d3 e8 03 45 ?? 89 45 ec 89 45 f0 8d 04 33 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

