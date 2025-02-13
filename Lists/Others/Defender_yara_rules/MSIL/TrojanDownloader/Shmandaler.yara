rule TrojanDownloader_MSIL_Shmandaler_A_2147709595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Shmandaler.A"
        threat_id = "2147709595"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shmandaler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/MHandler" wide //weight: 1
        $x_1_2 = {4d 41 67 65 6e 74 00 41 73 73 65 6d 62 6c 79 54}  //weight: 1, accuracy: High
        $x_1_3 = {21 4d 00 41 00 67 00 65 00 6e 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

