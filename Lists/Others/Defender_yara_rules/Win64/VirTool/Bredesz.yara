rule VirTool_Win64_Bredesz_A_2147982449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bredesz.A"
        threat_id = "2147982449"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bredesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 68 48 89 44 24 30 ?? ?? ?? ?? ?? 44 89 64 24 28 45 33 c0 33 d2 4c 89 64 24 20 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {45 8b c7 48 8b d6 b9 40 00 00 00 ff ?? ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d2 41 bc 04 01 00 00 bf 00 04 00 00 4c 8b cb 49 8b ce ?? ?? ?? ?? 83 fe 02 [0-16] 48 89 44 24 20 ff ?? ?? ?? ?? ?? 33 db 44 8b f0 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

