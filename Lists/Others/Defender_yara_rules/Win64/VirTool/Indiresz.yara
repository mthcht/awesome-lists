rule VirTool_Win64_Indiresz_A_2147962531_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Indiresz.A"
        threat_id = "2147962531"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Indiresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 05 00 00 00 80 7c 02 fb b8 ?? ?? 49 ff c3 48 ff c0 48 83 f8 40 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 4d 8b c4 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b d1 8b 05 [0-16] 4c 8b d1 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

