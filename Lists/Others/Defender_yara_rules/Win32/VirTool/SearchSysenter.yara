rule VirTool_Win32_SearchSysenter_A_2147955406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SearchSysenter.A"
        threat_id = "2147955406"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SearchSysenter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 0f c6 45 fd 34 c6 45 fe c3 33 c0 57 6a 03 59 8d 3c 10 8d 75 fc 33 db f3 a6 74 0d 40 83 f8 20 7c eb 33 c0 5f 5e 5b c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

