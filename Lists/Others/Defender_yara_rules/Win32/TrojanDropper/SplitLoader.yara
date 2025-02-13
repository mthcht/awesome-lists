rule TrojanDropper_Win32_SplitLoader_B_2147911600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/SplitLoader.B!dha"
        threat_id = "2147911600"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "SplitLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 8b f8 0f 11 85 ?? 00 00 00 0f 11 8d ?? 00 00 00 e8 ?? ?? ?? ?? 41 b9 ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 48 8d 54 24 40 48 8b cf e8}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

