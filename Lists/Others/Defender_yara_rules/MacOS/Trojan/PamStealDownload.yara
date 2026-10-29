rule Trojan_MacOS_PamStealDownload_A_2147981162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PamStealDownload.A"
        threat_id = "2147981162"
        type = "Trojan"
        platform = "MacOS: "
        family = "PamStealDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -s" wide //weight: 1
        $x_2_2 = "kernelops.pro/7elx7e/WQA4W6m31saR" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

