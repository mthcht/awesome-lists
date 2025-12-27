rule Trojan_MacOS_SuspNPMexfil_A_2147955243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspNPMexfil.A"
        threat_id = "2147955243"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspNPMexfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "curl" wide //weight: 3
        $x_3_2 = " -d " wide //weight: 3
        $x_3_3 = "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

