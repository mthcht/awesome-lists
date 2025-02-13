rule HackTool_Win64_Zenbleed_A_2147852250_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Zenbleed.A!dha"
        threat_id = "2147852250"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenbleed"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c5 fc 77 48 31 c0 48 0f 6e c0}  //weight: 1, accuracy: High
        $x_1_2 = {48 ff c9 66 0f 2a e0 66 0f 2a d8 66 0f 2a d0 66 0f 2a c8 66 0f 2a c0 c5 fd 6f c0 78 03 c5 f8 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

