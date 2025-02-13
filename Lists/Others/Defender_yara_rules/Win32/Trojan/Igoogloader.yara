rule Trojan_Win32_Igoogloader_RB_2147838578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Igoogloader.RB!MTB"
        threat_id = "2147838578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Igoogloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f bf 45 b4 b9 67 cb ff ff 2b c8 03 4d f0 8b 85 6c ff ff ff f7 d9 1b c9 41 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 03 8d 6c ff ff ff 4a 89 8d 6c ff ff ff 66 8b 45 e4 fe 05 ?? ?? ?? ?? b1 b3 f6 e9 88 45 f8 85 d2 7f b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

