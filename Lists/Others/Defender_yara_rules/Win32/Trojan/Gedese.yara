rule Trojan_Win32_Gedese_YA_2147731881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gedese.YA!MTB"
        threat_id = "2147731881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gedese"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/get_v2.php" wide //weight: 1
        $x_3_2 = "//api.2ip.ua/geo.json" wide //weight: 3
        $x_3_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_1_4 = "delself.bat" ascii //weight: 1
        $x_1_5 = "\"country_code\":\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

