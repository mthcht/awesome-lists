rule Trojan_Win64_Stealz_CH_2147958385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Stealz.CH!MTB"
        threat_id = "2147958385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "STEALER ACTIVATED" ascii //weight: 2
        $x_2_2 = "Chrome\\User Data\\Default\\Login Data" ascii //weight: 2
        $x_2_3 = "api.telegram.org/bot" ascii //weight: 2
        $x_2_4 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

