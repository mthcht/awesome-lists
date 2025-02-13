rule Trojan_MSIL_Adload_S_2147744440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Adload.S!MSR"
        threat_id = "2147744440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Adload"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 41 79 6d 65 6e 54 4c 49 4c 49 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c [0-16] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "/VERYSILENT /p=" wide //weight: 1
        $x_1_3 = "HadhrinaDoss" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "ups.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

