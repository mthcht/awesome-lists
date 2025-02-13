rule PWS_MSIL_Pasriever_A_2147723075_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Pasriever.A"
        threat_id = "2147723075"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pasriever"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Projects\\DPAPI\\DPAPI\\obj\\Release\\Vine.pdb" ascii //weight: 1
        $x_1_2 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 74 00 72 00 69 00 65 00 76 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "pass-{0}-{1}-{2}.csv" wide //weight: 1
        $x_1_4 = {2f 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 2f 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 2f 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 2f 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 [0-4] 74 00 65 00 6d 00 70 00 5f 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 [0-4] 6c 00 6f 00 67 00 69 00 6e 00 73 00 2e 00 6a 00 73 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_6 = "ChromeRetriever" ascii //weight: 1
        $x_1_7 = "FirefoxRetriever" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

