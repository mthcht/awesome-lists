rule Trojan_Win32_AStealer_GA_2147776488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AStealer.GA!MTB"
        threat_id = "2147776488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AStealer" ascii //weight: 1
        $x_1_2 = "SELECT * FROM logins" ascii //weight: 1
        $x_1_3 = "select *  from moz_logins" ascii //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_5 = "password" ascii //weight: 1
        $x_1_6 = "smtpserver" ascii //weight: 1
        $x_1_7 = "config.dyndns" ascii //weight: 1
        $x_1_8 = "JDOWNLOADER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

