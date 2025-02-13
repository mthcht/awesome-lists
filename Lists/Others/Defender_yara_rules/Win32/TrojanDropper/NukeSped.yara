rule TrojanDropper_Win32_NukeSped_PI_2147758632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/NukeSped.PI!MTB"
        threat_id = "2147758632"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 10 72 03 83 e9 ?? 8a 04 3a 32 44 0d e0 42 88 44 13 ef 41 3b d6 72}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 10 00 00 51 03 c3 50 ff ?? ?? ?? ?? ?? 85 c0 74 ?? 8b 46 04 ff 36 03 45 ?? 8b 7e fc 03 fb 50 57 e8 ?? ?? ?? ?? 89 7e f8 8b 55 fc 83 c4 0c 8b 45 0c 8b 7d f8 8b 00 47 0f b7 40 06 83 c6 ?? 89 7d f8 3b f8 0f 8c 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

