rule HackTool_Win64_GooseEgg_A_2147843370_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/GooseEgg.A!dha"
        threat_id = "2147843370"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GooseEgg"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {ef 16 35 0c c7 45 ?? 24 4a c6 4f c7 45 ?? c5 23 94 2b c7 45 ?? 1e ca 65 aa}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_GooseEgg_B_2147843371_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/GooseEgg.B!dha"
        threat_id = "2147843371"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GooseEgg"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {35 15 cd 5b 07 ?? ?? ?? ?? ?? ?? ?? 34 4f ?? ?? ?? ?? ?? ?? ?? 34 7b}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

