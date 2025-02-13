rule Trojan_Linux_RemovalOnHost_F_2147787272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RemovalOnHost.F"
        threat_id = "2147787272"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RemovalOnHost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rm -rf" wide //weight: 1
        $x_1_2 = "rm -fr" wide //weight: 1
        $x_1_3 = "rm -r -f" wide //weight: 1
        $x_1_4 = "rm -f -r" wide //weight: 1
        $x_5_5 = " / " wide //weight: 5
        $x_10_6 = "--no-preserve-root" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

