rule Trojan_Win32_Capface_A_2147621179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Capface.A"
        threat_id = "2147621179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Capface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dedlf.bat" ascii //weight: 10
        $x_10_2 = "img%d_%d.jpg" ascii //weight: 10
        $x_10_3 = "anti-captcha.com" ascii //weight: 10
        $x_10_4 = "<script language=\"javascript\">top.location='ht" wide //weight: 10
        $x_1_5 = "WinPostMX" ascii //weight: 1
        $x_1_6 = "212.95.51.35" ascii //weight: 1
        $x_1_7 = "newaccountcaptcha" ascii //weight: 1
        $x_1_8 = "https://www.google.com/accounts/Captcha?" ascii //weight: 1
        $x_1_9 = "/rd/mydd.php?hui=%s&hui2=%s&hui3=%s&file=elite03" ascii //weight: 1
        $x_1_10 = "/res.php?key=%s&action=get&id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Capface_B_2147635798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Capface.B"
        threat_id = "2147635798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Capface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WinPostMX" ascii //weight: 2
        $x_1_2 = "EnableFirewall" ascii //weight: 1
        $x_1_3 = "img%d_%d.jpg" ascii //weight: 1
        $x_1_4 = "newaccountcaptcha" ascii //weight: 1
        $x_1_5 = "<iframe src='javascript:top.location=\"ht" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

