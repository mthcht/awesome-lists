rule Trojan_PowerShell_PowDow_DG_2147960855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PowDow.DG!MTB"
        threat_id = "2147960855"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "brandingsolutionstore.com/static_image/" wide //weight: 10
        $x_1_2 = "curl --insecure" wide //weight: 1
        $x_1_3 = "-X POST -d" wide //weight: 1
        $x_1_4 = "-sSL -H" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

