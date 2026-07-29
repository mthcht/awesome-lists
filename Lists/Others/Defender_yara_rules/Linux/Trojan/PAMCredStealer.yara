rule Trojan_Linux_PAMCredStealer_A_2147974715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PAMCredStealer.A"
        threat_id = "2147974715"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PAMCredStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "gcc " wide //weight: 5
        $x_5_2 = "clang " wide //weight: 5
        $x_10_3 = "-shared" wide //weight: 10
        $x_10_4 = "-lpam" wide //weight: 10
        $x_10_5 = "-lcurl" wide //weight: 10
        $x_10_6 = "-o /tmp/" wide //weight: 10
        $x_5_7 = ".so" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

