rule Trojan_Linux_SecGrep_Z_2147971292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SecGrep.Z!MTB"
        threat_id = "2147971292"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SecGrep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tr -d '\\0'" wide //weight: 1
        $x_1_2 = "| grep -aoE" wide //weight: 1
        $x_1_3 = "isSecret\":true" wide //weight: 1
        $x_1_4 = "value\":" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

