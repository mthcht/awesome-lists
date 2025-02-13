rule SupportScam_Win32_Monitnev_A_2147720495_0
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:Win32/Monitnev.A"
        threat_id = "2147720495"
        type = "SupportScam"
        platform = "Win32: Windows 32-bit platform"
        family = "Monitnev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EM_SYS_MONITOR_" wide //weight: 1
        $x_1_2 = {76 00 65 00 72 00 3d 00 25 00 73 00 26 00 69 00 73 00 72 00 65 00 67 00 3d 00 25 00 64 00 26 00 72 00 65 00 67 00 6b 00 65 00 79 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "utm_source=<utm_src>&utm_campaign=<utm_cpgn>&utm_medium=<utm_med>" wide //weight: 1
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "ininotfound%d.ini" wide //weight: 1
        $x_1_6 = "IsTelNoEnabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SupportScam_Win32_Monitnev_A_2147720495_1
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:Win32/Monitnev.A"
        threat_id = "2147720495"
        type = "SupportScam"
        platform = "Win32: Windows 32-bit platform"
        family = "Monitnev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".fullpccare.com/em/update2.asp" wide //weight: 1
        $x_1_2 = "ver=%s&isreg=%d&regkey=%s&prd=em" wide //weight: 1
        $x_1_3 = "utm_source=<utm_src>&utm_campaign=<utm_cpgn>&utm_medium=<utm_med>" wide //weight: 1
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 45 00 76 00 65 00 6e 00 74 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "ininotfound%d.ini" wide //weight: 1
        $x_1_6 = "IsTelNoEnabled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

