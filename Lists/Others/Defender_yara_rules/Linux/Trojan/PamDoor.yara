rule Trojan_Linux_PamDoor_A_2147971310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/PamDoor.A"
        threat_id = "2147971310"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "PamDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Skipping non-SSH:" ascii //weight: 1
        $x_1_2 = "https://jsscript.net/report.php" ascii //weight: 1
        $x_1_3 = "User-Agent: PAM-SSH-Monitor/2.0" ascii //weight: 1
        $x_1_4 = "pam_report:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

