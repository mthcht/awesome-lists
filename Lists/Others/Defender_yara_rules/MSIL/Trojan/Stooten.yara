rule Trojan_MSIL_Stooten_A_2147706838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stooten.A"
        threat_id = "2147706838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stooten"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "httpflood" wide //weight: 1
        $x_1_2 = "synflood" wide //weight: 1
        $x_1_3 = "/connect.php" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

