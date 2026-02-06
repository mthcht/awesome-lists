rule VirTool_Win64_Diresez_A_2147962530_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Diresez.A"
        threat_id = "2147962530"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Diresez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 05 00 00 00 42 80 7c 00 fb b8 ?? ?? 48 ff c3 48 ff c0 48 83 f8 40 ?? ?? b9 02 00 00 00 ff ?? ?? ?? ?? ?? 4c 8b c6 ?? ?? ?? ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8b d1 8b 05 ?? ?? ?? ?? 0f 05 c3 4c 8b d1 8b 05 ?? ?? ?? ?? 0f 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

