rule VirTool_Win64_Silepesz_A_2147958745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Silepesz.A"
        threat_id = "2147958745"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Silepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ff ?? 48 85 c0 ?? ?? 48 ba d9 92 fb 55 9a ac 70 e0 48 89 c1 e8 ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? 45 31 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 24 29 00 c6 44 24 49 77 c6 44 24 4a 6f c6 44 24 4b 72 c6 44 24 4c 6c c6 44 24 4d 64 c6 44 24 4e 21 c6 44 24 25 44 c6 44 24 26 65 c6 44 24 27 6d c6 44 24 28 6f e8 ?? ?? ?? ?? 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

