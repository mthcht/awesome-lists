rule Trojan_Win32_Reppop_A_2147614119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reppop.A"
        threat_id = "2147614119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reppop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "135"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "frmPopper" ascii //weight: 10
        $x_10_2 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" ascii //weight: 10
        $x_10_3 = "C:\\Users\\jweek\\Desktop\\AdSoft_App\\popper\\popper.vbp" wide //weight: 10
        $x_10_4 = "co.uk" wide //weight: 10
        $x_10_5 = "com.au" wide //weight: 10
        $x_10_6 = "failed to load masked domains" wide //weight: 10
        $x_10_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_8 = "startup key added" wide //weight: 10
        $x_10_9 = "filterHtml ERROR:" wide //weight: 10
        $x_10_10 = "parseKeywords ERROR:" wide //weight: 10
        $x_10_11 = "\\temp1.txt" wide //weight: 10
        $x_10_12 = "SysMon321.exe" wide //weight: 10
        $x_10_13 = ".info" wide //weight: 10
        $x_1_14 = "emule" wide //weight: 1
        $x_1_15 = "kserver" wide //weight: 1
        $x_1_16 = "thebi" wide //weight: 1
        $x_1_17 = "phantine" wide //weight: 1
        $x_1_18 = "tahserve" wide //weight: 1
        $x_1_19 = "otcoupe" wide //weight: 1
        $x_1_20 = "dingal" wide //weight: 1
        $x_1_21 = "atolo" wide //weight: 1
        $x_1_22 = "gical" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

