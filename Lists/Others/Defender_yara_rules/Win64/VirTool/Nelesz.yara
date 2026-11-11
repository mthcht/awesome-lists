rule VirTool_Win64_Nelesz_A_2147981847_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nelesz.A"
        threat_id = "2147981847"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4d c8 48 89 4d 70 ba 01 00 00 00 41 b8 40 00 00 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 45 54 83 f8 00 ?? ?? 48 8b 4d c8 ba c3 00 00 00 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 28 48 8b 54 24 30 41 89 c0 ff ?? ?? ?? ?? ?? 89 44 24 4c}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b 4d cc 49 89 c0 4c 89 85 f0 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? b9 0d 00 00 00 ff ?? 48 89 c1 48 89 c8 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

