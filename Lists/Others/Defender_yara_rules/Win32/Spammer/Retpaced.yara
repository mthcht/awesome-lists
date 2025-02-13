rule Spammer_Win32_Retpaced_A_2147690857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Retpaced.A"
        threat_id = "2147690857"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Retpaced"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0" wide //weight: 2
        $x_2_2 = "image/png,image/*;q=0.8,*/*;q=0.5" wide //weight: 2
        $x_2_3 = "ko-kr,ko;q=0.8,en-us;q=0.5,en;q=0.3" wide //weight: 2
        $x_6_4 = "http://popall.com/lin/bbs.htm?code=talking&mode=1" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_Retpaced_B_2147693898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Retpaced.B"
        threat_id = "2147693898"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Retpaced"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://1.234.66.143/svchost.exe" wide //weight: 1
        $x_1_2 = "\\Injector\\Project" wide //weight: 1
        $x_1_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

