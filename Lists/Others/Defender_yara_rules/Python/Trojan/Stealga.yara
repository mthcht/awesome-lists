rule Trojan_Python_Stealga_DB_2147939988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Python/Stealga.DB!MTB"
        threat_id = "2147939988"
        type = "Trojan"
        platform = "Python: Python scripts"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CookiesParses" ascii //weight: 10
        $x_10_2 = "Chromium" ascii //weight: 10
        $x_10_3 = "pass.html" ascii //weight: 10
        $x_10_4 = "PC.html" ascii //weight: 10
        $x_10_5 = "cookies.zip" ascii //weight: 10
        $x_1_6 = "get_passwords" ascii //weight: 1
        $x_1_7 = "get_cookies" ascii //weight: 1
        $x_1_8 = "get_wifi" ascii //weight: 1
        $x_1_9 = "get_mac" ascii //weight: 1
        $x_1_10 = "getenv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

