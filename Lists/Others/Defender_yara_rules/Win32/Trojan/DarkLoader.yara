rule Trojan_Win32_DarkLoader_DF_2147798614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkLoader.DF!MTB"
        threat_id = "2147798614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AntiStealerByDark" ascii //weight: 3
        $x_3_2 = "gethostbyname" ascii //weight: 3
        $x_3_3 = "wspath.phpwspath.phpwspath.phpwspath.php?" ascii //weight: 3
        $x_3_4 = "wslink.php?" ascii //weight: 3
        $x_3_5 = "gta_sa_exe" ascii //weight: 3
        $x_3_6 = "Ashot Samp" ascii //weight: 3
        $x_3_7 = "darkloader.ru" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

