rule VirTool_Win64_Bruterat_C_2147893557_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bruterat.C"
        threat_id = "2147893557"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c1 01 48 39 c8 74 17 80 39 ?? 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c8 83 c0 ?? 45 0f b6 04 09 0f b7 ca 83 c2 ?? 44 88 44 0c 20 66 41 39 c2 77 e4}  //weight: 1, accuracy: Low
        $x_1_3 = {66 45 85 d2 74 21 31 d2 31 c0 ?? 0f b7 c8 83 c0 ?? 45 0f b6 04 09 0f b7 ca 83 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

