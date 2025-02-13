rule PWS_Win32_Fonfrep_A_2147659885_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fonfrep.A"
        threat_id = "2147659885"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fonfrep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Mozilla\\Firefox\\profiles.ini" wide //weight: 1
        $x_1_2 = "select *  from moz_logins" wide //weight: 1
        $x_1_3 = "_+_+_pass_+_+_" wide //weight: 1
        $x_2_4 = "C:\\Users\\Owner\\Desktop\\FF\\S\\prjFF.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

