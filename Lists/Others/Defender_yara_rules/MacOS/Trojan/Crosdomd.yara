rule Trojan_MacOS_Crosdomd_A_2147966415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Crosdomd.A!MTB"
        threat_id = "2147966415"
        type = "Trojan"
        platform = "MacOS: "
        family = "Crosdomd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -o" wide //weight: 1
        $x_10_2 = "com.apple.act.mond " wide //weight: 10
        $x_10_3 = "sfrclak.com" wide //weight: 10
        $x_1_4 = "chmod 770" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

