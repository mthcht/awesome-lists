rule Trojan_Linux_BuhtiRansom_A_2147848616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BuhtiRansom.A"
        threat_id = "2147848616"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BuhtiRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Welcome to buhtiRansom" ascii //weight: 5
        $x_1_2 = "Your files are encrypted" ascii //weight: 1
        $x_1_3 = "Pay amount to Bitcoin address" ascii //weight: 1
        $x_1_4 = "Decrypt instruction included" ascii //weight: 1
        $x_1_5 = "main.encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

