rule Trojan_MacOS_ClickFix_DA_2147965640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/ClickFix.DA!MTB"
        threat_id = "2147965640"
        type = "Trojan"
        platform = "MacOS: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl -skfSL" wide //weight: 10
        $x_10_2 = "curl -sSfL" wide //weight: 10
        $x_10_3 = "curl -fsSL" wide //weight: 10
        $x_5_4 = "$(echo " wide //weight: 5
        $x_1_5 = "base64 -D" wide //weight: 1
        $x_1_6 = "base64 --d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

