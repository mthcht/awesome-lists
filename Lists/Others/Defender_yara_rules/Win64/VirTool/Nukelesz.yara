rule VirTool_Win64_Nukelesz_A_2147982776_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nukelesz.A"
        threat_id = "2147982776"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nukelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c6 84 db ?? ?? ?? ?? ?? ?? 49 b9 fc 81 86 1b 45 06 be c6 41 b8 0e 00 00 00 [0-18] e8}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 85 ff 0f 94 c3 4d 85 f6 0f 94 c2 09 d3 48 85 c0 0f 94 c2 08 d3 ?? ?? 48 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 0e 00 00 00 [0-19] e8 [0-18] 48 8b 5c 24 28 e8 ?? ?? ?? ?? 48 89 c6 80 38 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

