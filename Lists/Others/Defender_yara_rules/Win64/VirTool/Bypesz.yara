rule VirTool_Win64_Bypesz_A_2147958744_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypesz.A"
        threat_id = "2147958744"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff cf 48 ff c9 48 83 f9 01 ?? ?? ?? ?? ?? ?? 80 3f 74 ?? ?? 48 0f be 47 01 ?? ?? ?? ?? 48 81 fa ff 0f 00 00 ?? ?? 80 7c 07 02 b8 ?? ?? c7 44 24 28 00 00 00 00 ?? ?? ?? ?? ?? ba 01 00 00 00 48 89 f9 41}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 14 08 44 0f b6 44 08 02 41 c1 e0 10 41 09 d0 41 81 f8 c3 cc cc 00 ?? ?? 0f b7 54 08 01 44 0f b6 44 08 03 41 c1 e0 10 41 09 d0 41 81 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

