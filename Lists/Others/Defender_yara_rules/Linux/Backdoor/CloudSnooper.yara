rule Backdoor_Linux_CloudSnooper_A_2147773015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/CloudSnooper.gen!A!!Cloudsnooper.gen!A"
        threat_id = "2147773015"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "CloudSnooper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Cloudsnooper: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cloud.newsofnp.com" ascii //weight: 5
        $x_5_2 = "ssl.newsofnp.com" ascii //weight: 5
        $x_5_3 = "62.113.255.18" ascii //weight: 5
        $x_5_4 = "89.33.246.111" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

