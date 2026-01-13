rule VirTool_Win64_Bypegesz_A_2147961072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Bypegesz.A"
        threat_id = "2147961072"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Bypegesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 e8 ?? ?? ?? ?? b9 01 00 00 00 48 89 c2 ?? ?? ?? ?? ?? ?? ?? 48 29 d0 ?? ?? ?? ?? ?? ?? 48 89 c3 48 85 c0 [0-18] 48 c7 44 24 48 01 00 00 00 41 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 48 85 c0 ?? ?? 48 8b 0b 48 8b 43 08 48 39 51 10 ?? ?? 48 8b ?? 98 00 00 00 45 31 c0 48 8b 4a 30 48 83 c2 08 44 89 01 48 8b 4a f8 48 89 ?? 98 00 00 00 48 89 88 f8 00 00 00 81 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

