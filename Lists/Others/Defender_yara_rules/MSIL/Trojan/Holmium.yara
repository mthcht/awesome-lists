rule Trojan_MSIL_Holmium_SA_2147741600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Holmium.SA!dha"
        threat_id = "2147741600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Holmium"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Baseball.php" wide //weight: 2
        $x_1_2 = "\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe" wide //weight: 1
        $x_2_3 = "https://193.37.212.26/" wide //weight: 2
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Universal Windows Platform\\Registered" wide //weight: 1
        $x_2_5 = "$336edac9-2385-4d92-916c-f77a3b995c6b" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

