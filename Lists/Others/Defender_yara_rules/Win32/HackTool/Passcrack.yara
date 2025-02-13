rule HackTool_Win32_Passcrack_2147696305_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Passcrack"
        threat_id = "2147696305"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Passcrack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%4d-%02d-%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_2 = "Usage:crack  user.txt pass.txt" ascii //weight: 1
        $x_1_3 = "User:%s Pass:%s Domian:%s" ascii //weight: 1
        $x_1_4 = "Loading user name password dictionary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

