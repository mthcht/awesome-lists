rule Trojan_Linux_SusCredDisc_GA_2147982307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SusCredDisc.GA!MTB"
        threat_id = "2147982307"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SusCredDisc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "grep -r" wide //weight: 3
        $x_2_2 = "(admin|rancher)" wide //weight: 2
        $x_2_3 = "(pass|pwd|secret)" wide //weight: 2
        $x_5_4 = "(pass(word|wd)?)[ ]*[=:][ ]*[^ ]{4,}" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

