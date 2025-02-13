rule HackTool_Win32_ZorKey_A_2147894762_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ZorKey.A!dha"
        threat_id = "2147894762"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorKey"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "iieunh523Xsaw" wide //weight: 100
        $x_100_2 = "k03 " wide //weight: 100
        $x_100_3 = {7b 00 43 00 31 00 7d 00 00 00 00 00 7b 00 43 00 32 00 7d 00 00 00 00 00 7b 00 41 00 44 00 44 00 7d}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

