rule Trojan_MacOS_ClawHavoc_DA_2147965429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ClawHavoc.DA!MTB"
        threat_id = "2147965429"
        type = "Trojan"
        platform = "MacOS: "
        family = "ClawHavoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&& curl -O http://" wide //weight: 1
        $x_1_2 = "&& xattr -c" wide //weight: 1
        $x_1_3 = "&& chmod +x" wide //weight: 1
        $x_1_4 = "&& ./" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_ClawHavoc_DB_2147965430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ClawHavoc.DB!MTB"
        threat_id = "2147965430"
        type = "Trojan"
        platform = "MacOS: "
        family = "ClawHavoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 63 00 68 00 6f 00 [0-255] 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 44 00}  //weight: 1, accuracy: Low
        $x_1_2 = "bash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

