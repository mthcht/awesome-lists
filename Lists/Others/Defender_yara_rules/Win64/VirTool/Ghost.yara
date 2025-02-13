rule VirTool_Win64_Ghost_B_2147924494_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Ghost.B"
        threat_id = "2147924494"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Ghost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 81 ec 00 01 00 00 48 89 74 24 08 48 89 7c 24 10 4c 89 64 24 18 49 89 ca ?? ?? ?? ?? ?? ?? ?? 48 81 ec 00 02 00 00 4c 89 04 24 48 83 fa 00 ?? ?? 49 89 d3 48 83 fa 04 4c 89 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 94 24 28 03 00 00 4c 8b 84 24 30 03 00 00 4c 8b 8c 24 38 03 00 00 ?? ?? 48 89 c8 4c 89 d9 48 83 e9 04 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? f3 48 a5 48 89 c1 41 ff e2 48 8b b4 24 08 02 00 00 48 8b bc 24 10 02 00 00 4c 8b a4 24 18 02 00 00 48 81 c4 00 03 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

