rule HackTool_Win32_IEPassview_2147689551_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/IEPassview"
        threat_id = "2147689551"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "IEPassview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "IE PassView" ascii //weight: 5
        $x_5_2 = "nirsoft.net" ascii //weight: 5
        $x_1_3 = "iepv_sites.txt" ascii //weight: 1
        $x_2_4 = {73 76 65 72 68 74 6d 6c 00 00 00 2f 73 78 6d 6c 00 00 00 2f 73 74 61 62}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

