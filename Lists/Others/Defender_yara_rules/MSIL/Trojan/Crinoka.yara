rule Trojan_MSIL_Crinoka_A_2147712084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crinoka.A"
        threat_id = "2147712084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crinoka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 63 70 66 6c 6f 6f 64 00 74 63 70 62 79 70 61 73 73 00 74 63 70 63 6f 6e 6e 65 63 74 00 74 63 70 45 78 68 61 75 73 74 00}  //weight: 2, accuracy: High
        $x_1_2 = "Crino.Actions" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "WindowsUpdater.exe" wide //weight: 1
        $x_1_5 = "\\AppData\\Roaming\\kernel.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

