rule VirTool_Win32_EDRBlok_B_2147950828_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/EDRBlok.B"
        threat_id = "2147950828"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "EDRBlok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 f4 00 00 00 00 ?? ?? ?? c7 45 f8 00 00 00 00 bb 01 00 00 00 33 ff 50 6a 08 6a ff ff ?? ?? ?? ?? ?? 85 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 45 f4 00 00 00 00 50 6a 08 6a ff bf 01 00 00 00 c7 45 f8 00 00 00 00 33 db ff ?? ?? ?? ?? ?? 85 c0}  //weight: 5, accuracy: Low
        $x_1_3 = {83 c4 08 8d ?? ?? 50 6a 00 6a 00 6a 19 ff 75 f4 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 0c ff ?? ff ?? ?? ?? ?? ?? 0f b6 00 48 50 ff ?? ff ?? ?? ?? ?? ?? 8b 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

