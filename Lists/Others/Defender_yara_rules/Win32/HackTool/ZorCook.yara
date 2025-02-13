rule HackTool_Win32_ZorCook_A_2147894763_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ZorCook.A!dha"
        threat_id = "2147894763"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorCook"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "iieunh523Xsaw" wide //weight: 100
        $x_100_2 = "Something gone wrong. Ch" wide //weight: 100
        $x_100_3 = "Ch.slte" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

