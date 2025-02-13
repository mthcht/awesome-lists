rule Backdoor_MSIL_Sylavriu_A_2147692651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sylavriu.A"
        threat_id = "2147692651"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sylavriu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {53 6c 61 76 65 4f 6e 6c 69 6e 65 00 77 65 62 00 73 65 6e 64 62 61 63 6b}  //weight: 3, accuracy: High
        $x_3_2 = "Projects\\WebRemote TorCT Server" ascii //weight: 3
        $x_2_3 = "/SlaveOnline.php" wide //weight: 2
        $x_2_4 = "/AddFNActive.php" wide //weight: 2
        $x_2_5 = "BlackScreenNC747" wide //weight: 2
        $x_2_6 = "DownloadFIleToComputer747:" wide //weight: 2
        $x_1_7 = "Gebruiker\\Documents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

