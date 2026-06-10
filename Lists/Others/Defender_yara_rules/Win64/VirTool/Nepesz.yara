rule VirTool_Win64_Nepesz_A_2147971338_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nepesz.A"
        threat_id = "2147971338"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 df 45 33 c9 45 33 c0 4c 89 64 24 20 48 8b cb ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 8b d0 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 55 df 48 8b 4d d7 4c 89 64 24 20 ff ?? ?? ?? ?? ?? 8b d8 85 c0 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 41 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

