rule VirTool_Win64_Shelodesz_A_2147960263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelodesz.A"
        threat_id = "2147960263"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 49 03 d1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff c0 32 0a ?? ?? ?? ?? fe c1 88 4a ff 41 3b c0 ?? ?? 48 83 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b c1 49 8b c9 e8 ?? ?? ?? ?? ?? ?? 49 2b d1 ?? ?? ?? ?? 48 2b ce 66 ?? 41 0f b6 04 10 41 88 00 ?? ?? ?? ?? 48 83 e9 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

