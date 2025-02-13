rule Trojan_Win32_Webnav_A_2147642521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webnav.A!dll"
        threat_id = "2147642521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webnav"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 93 24 49 92 f7 e9 03 d1 c1 fa 04 8b fa c1 ef 1f 03 fa}  //weight: 2, accuracy: High
        $x_1_2 = ":\\windows\\system32\\index.html" ascii //weight: 1
        $x_1_3 = "360seURL\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 77 69 73 65 73 6f 66 74 5c 00}  //weight: 1, accuracy: High
        $x_1_5 = "htmlfile\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "Explorer\\iexplore.exe\" \"%1\"" ascii //weight: 1
        $x_1_7 = "\\wisesoft\\config.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

