rule VirTool_Win64_Celodesz_A_2147975259_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Celodesz.A"
        threat_id = "2147975259"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Celodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 40 4c 89 7c 24 38 4c 89 7c 24 30 c7 44 24 28 00 00 00 08 44 89 7c 24 20 45 33 c9 45 33 c0 33 c9 ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 7d 10 4c 89 7d 18 b9 10 02 00 00 e8 ?? ?? ?? ?? 48 89 45 00 48 c7 45 10 0a 02 00 00 48 c7 45 18 0f 02 00 00 48 8b c8}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 45 10 48 83 f8 07 ?? ?? ?? ?? ?? ?? 41 b9 07 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 48 8b cf e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

