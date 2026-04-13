rule VirTool_Win64_Pesedesz_A_2147966881_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pesedesz.A"
        threat_id = "2147966881"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pesedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f3 0f 7f 44 24 50 c6 44 24 70 3a f3 0f 7f 4c 24 60 ?? ?? ?? ?? e8 [0-18] ba 21 00 00 00 ?? ?? ?? ?? ?? e8 [0-23] ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 48 8b 9a b8 00 00 00 48 8b f2 48 8b e9 81 7b 18 1b 00 12 00 ?? ?? 83 7b 10 70 ?? ?? ba 20 00 00 00 33 c9 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {48 33 c4 48 89 44 24 50 83 7a 30 00 49 8b f8 4c 8b ba b8 00 00 00 48 8b da 4c 8b e9 ?? ?? ?? ?? ?? ?? 48 8b 72 70 48 83 7e 30 38 ?? ?? ?? ?? ?? ?? 49 8b 48 18 ?? ?? ?? ?? ?? 44 8b 66 68 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

