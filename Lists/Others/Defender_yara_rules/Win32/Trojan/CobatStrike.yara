rule Trojan_Win32_CobatStrike_NBL_2147896412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobatStrike.NBL!MTB"
        threat_id = "2147896412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobatStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 05 89 45 fc 8b 45 f0 01 45 fc 8b 45 f8 8b fb c1 e7 04 03 7d ec 03 c3 33 f8 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 0a 6a 00 6a 00 ff 15 2c 30 43 00 31 7d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

