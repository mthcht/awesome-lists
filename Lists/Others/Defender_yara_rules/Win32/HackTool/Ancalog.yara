rule HackTool_Win32_Ancalog_A_2147717900_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Ancalog.A"
        threat_id = "2147717900"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ancalog"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ancalog Multi Exploit Builder" ascii //weight: 1
        $x_1_2 = "MS Word Doc exploited macro USG" ascii //weight: 1
        $x_1_3 = "MS Excel XLS exploited macro USG" ascii //weight: 1
        $x_1_4 = "Silent exploit method:" ascii //weight: 1
        $x_1_5 = "Regular exploit method:" ascii //weight: 1
        $x_1_6 = "Silent DOC Exploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Win32_Ancalog_B_2147717902_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Ancalog.B"
        threat_id = "2147717902"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ancalog"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://ancalog.win/auth/" ascii //weight: 1
        $x_1_2 = "Use this file to infect victim" ascii //weight: 1
        $x_1_3 = "Exploit Builder" ascii //weight: 1
        $x_1_4 = "%%HAXX%%" ascii //weight: 1
        $x_1_5 = "/bypass.dll" ascii //weight: 1
        $x_1_6 = "/user.bin" ascii //weight: 1
        $x_1_7 = "/htm.bin" ascii //weight: 1
        $x_1_8 = "/exp.dll" ascii //weight: 1
        $x_1_9 = "/fl.dll" ascii //weight: 1
        $x_1_10 = "cve2015-2545bypass.doc" ascii //weight: 1
        $x_1_11 = "YourExploit.pdf" ascii //weight: 1
        $x_1_12 = "YourSilentExploit.doc" ascii //weight: 1
        $x_1_13 = "YourMacroExploit.doc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Ancalog_C_2147717903_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Ancalog.C"
        threat_id = "2147717903"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ancalog"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TLazLogger" ascii //weight: 1
        $x_1_2 = "Exploit Builder" ascii //weight: 1
        $x_1_3 = "Use this software only for educational purposes and penetration tests. No illegal activities!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Ancalog_D_2147717924_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Ancalog.D"
        threat_id = "2147717924"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ancalog"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TLazLogger" ascii //weight: 1
        $x_1_2 = "Exploit Builder" ascii //weight: 1
        $x_1_3 = "/For penetration tests only!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

