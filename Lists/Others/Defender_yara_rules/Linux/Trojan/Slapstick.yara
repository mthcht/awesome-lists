rule Trojan_Linux_Slapstick_AMTB_2147958478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Slapstick!AMTB"
        threat_id = "2147958478"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Slapstick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%-23s %-23s %-23s %-23s %-23s %s" ascii //weight: 1
        $x_1_2 = "pam_sm_authenticate" ascii //weight: 1
        $x_1_3 = "HISTFILE=/dev/null" ascii //weight: 1
        $x_1_4 = "%-23s %-23s %-23s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

