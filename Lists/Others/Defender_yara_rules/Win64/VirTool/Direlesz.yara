rule VirTool_Win64_Direlesz_A_2147958746_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Direlesz.A"
        threat_id = "2147958746"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Direlesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d8 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ba 01 00 00 00 41 b8 40 00 00 00 48 8b c8 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? c6 03 c3 ?? ?? ?? ?? ?? 44 8b 44 24 30 ba 01 00 00 00 48 8b cb ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ba a1 03 00 00 3b fa ?? ?? 8b c7 ?? ?? ?? ?? ?? ?? ?? 48 03 c8 2b d7 8b c2 ?? ?? ?? ?? ?? 80 31 aa ?? ?? ?? ?? 48 83 e8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

