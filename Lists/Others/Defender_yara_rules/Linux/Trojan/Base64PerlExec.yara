rule Trojan_Linux_Base64PerlExec_MDD_2147972536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Base64PerlExec.MDD!MTB"
        threat_id = "2147972536"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Base64PerlExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sleep" wide //weight: 1
        $x_1_2 = "|base64" wide //weight: 1
        $x_1_3 = "--decode" wide //weight: 1
        $x_1_4 = "nohup perl" wide //weight: 1
        $x_1_5 = "/dev/null 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

