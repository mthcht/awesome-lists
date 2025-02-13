rule Trojan_Win64_Konirat_A_2147729492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Konirat.A"
        threat_id = "2147729492"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Konirat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wirbiry2jsq3454.exe" wide //weight: 1
        $x_1_2 = "weewyesqsf4.exe" wide //weight: 1
        $x_1_3 = "mail.apm.co.kr" wide //weight: 1
        $x_1_4 = "./pds/data/upload.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

