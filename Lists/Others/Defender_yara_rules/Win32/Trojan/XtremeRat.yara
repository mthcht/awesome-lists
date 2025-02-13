rule Trojan_Win32_XtremeRat_A_2147743798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XtremeRat.A!!XtremeRat.gen!A"
        threat_id = "2147743798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XtremeRat"
        severity = "Critical"
        info = "XtremeRat: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XtremeKe" ascii //weight: 1
        $x_1_2 = "ftp.ftpserver.com" ascii //weight: 1
        $x_1_3 = "Xtreme RAT" ascii //weight: 1
        $x_1_4 = "%NOINJECT%" ascii //weight: 1
        $x_1_5 = "restart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_XtremeRat_A_2147743869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XtremeRat.A!MTB"
        threat_id = "2147743869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XtremeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XtremeKe" ascii //weight: 1
        $x_1_2 = "ftp.ftpserver.com" ascii //weight: 1
        $x_1_3 = "Xtreme RAT" ascii //weight: 1
        $x_1_4 = "%NOINJECT%" ascii //weight: 1
        $x_1_5 = "restart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

