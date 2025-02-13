rule Trojan_Linux_HideUserAccounts_A_2147919414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/HideUserAccounts.A"
        threat_id = "2147919414"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "HideUserAccounts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gsettings set" wide //weight: 10
        $x_10_2 = "org.gnome.login-screen" wide //weight: 10
        $x_10_3 = "disable-user-list" wide //weight: 10
        $x_10_4 = "true" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

