rule Trojan_Linux_ProfileMod_B_2147966019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProfileMod.B"
        threat_id = "2147966019"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProfileMod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "echo " wide //weight: 10
        $x_10_2 = "sudo " wide //weight: 10
        $x_10_3 = " insmod " wide //weight: 10
        $x_10_4 = ".bash_profile " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

