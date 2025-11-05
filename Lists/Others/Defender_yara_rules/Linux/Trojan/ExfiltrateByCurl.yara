rule Trojan_Linux_ExfiltrateByCurl_FO8_2147956841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ExfiltrateByCurl.FO8"
        threat_id = "2147956841"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ExfiltrateByCurl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -d" wide //weight: 1
        $x_1_2 = "//webhook.site" wide //weight: 1
        $x_1_3 = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

