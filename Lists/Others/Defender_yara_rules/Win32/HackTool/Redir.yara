rule HackTool_Win32_Redir_HAB_2147956301_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Redir.HAB!MTB"
        threat_id = "2147956301"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Redir"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 65 00 78 00 65 00 20 00 62 00 69 00 6e 00 64 00 20 00 3c 00 [0-18] 61 00 74 00 68 00 3e 00 20 00 3c 00 [0-18] 61 00 74 00 68 00 3e 00}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 65 78 65 20 62 69 6e 64 20 3c [0-18] 61 74 68 3e 20 3c [0-18] 61 74 68 3e}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 65 00 78 00 65 00 20 00 62 00 69 00 6e 00 64 00 20 00 [0-18] 61 00 74 00 68 00 20 00 [0-18] 61 00 74 00 68 00}  //weight: 10, accuracy: Low
        $x_10_4 = {2e 65 78 65 20 62 69 6e 64 20 [0-18] 61 74 68 20 [0-18] 61 74 68}  //weight: 10, accuracy: Low
        $x_5_5 = {2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 6f 00 75 00 64 00 20 00 3c 00 [0-18] 61 00 74 00 68 00 3e 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 5, accuracy: Low
        $x_5_6 = {2e 65 78 65 20 63 6c 6f 75 64 20 3c [0-18] 61 74 68 3e 20 63 72 65 61 74 65}  //weight: 5, accuracy: Low
        $x_5_7 = {2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 6f 00 75 00 64 00 20 00 [0-18] 61 00 74 00 68 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 5, accuracy: Low
        $x_5_8 = {2e 65 78 65 20 63 6c 6f 75 64 20 [0-18] 61 74 68 20 63 72 65 61 74 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

