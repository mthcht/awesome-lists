rule Virus_Win32_Wak_A_2147599830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Wak.A"
        threat_id = "2147599830"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Wak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\BLACK-DAY.EXE" ascii //weight: 1
        $x_1_2 = "\\autorun.inf" ascii //weight: 1
        $x_1_3 = ".ASPX" ascii //weight: 1
        $x_1_4 = ".HTML" ascii //weight: 1
        $x_1_5 = "By : wswhacker" ascii //weight: 1
        $x_1_6 = "Hi,Friend:" ascii //weight: 1
        $x_1_7 = "Your computer were infect my worm!" ascii //weight: 1
        $x_1_8 = "Please add my QQ Num:5188340,87408749,76665639" ascii //weight: 1
        $x_1_9 = "The worm Name:Black-Day" ascii //weight: 1
        $x_1_10 = "avp.exe" ascii //weight: 1
        $x_1_11 = "\\interview.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

