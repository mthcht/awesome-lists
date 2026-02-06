rule Trojan_AIGen_ClawHavoc_A_2147962520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AIGen/ClawHavoc.A"
        threat_id = "2147962520"
        type = "Trojan"
        platform = "AIGen: "
        family = "ClawHavoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "cmd" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "/bin/bash" wide //weight: 1
        $x_100_5 = "http://91.92.242.30" wide //weight: 100
        $x_100_6 = "http://95.92.242.30" wide //weight: 100
        $x_100_7 = "http://96.92.242.30" wide //weight: 100
        $x_100_8 = "http://202.161.50.59" wide //weight: 100
        $x_100_9 = "http://54.91.154.110" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_AIGen_ClawHavoc_B_2147962521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AIGen/ClawHavoc.B"
        threat_id = "2147962521"
        type = "Trojan"
        platform = "AIGen: "
        family = "ClawHavoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Setup-Wizard" wide //weight: 1
        $x_1_2 = {65 00 63 00 68 00 6f 00 90 00 02 00 ff 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 44 00 90 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "bash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

