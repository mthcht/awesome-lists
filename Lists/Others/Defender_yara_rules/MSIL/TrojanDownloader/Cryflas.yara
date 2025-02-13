rule TrojanDownloader_MSIL_Cryflas_B_2147681067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Cryflas.B"
        threat_id = "2147681067"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryflas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "burcuesmersoy.org/download.txt" wide //weight: 10
        $x_10_2 = "burcuesmersoy.org/indir.txt" wide //weight: 10
        $x_4_3 = {66 6c 61 73 68 70 6c 61 79 65 72 5f 4c 6f 61 64 00 74 69 6d 65 72 5f 32 5f 54 69 63 6b}  //weight: 4, accuracy: High
        $x_1_4 = "C:\\Windows\\csrss.exe" wide //weight: 1
        $x_1_5 = "Windows\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Cryflas_C_2147681068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Cryflas.C"
        threat_id = "2147681068"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryflas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "java-downloader.com/indir.txt" wide //weight: 10
        $x_4_2 = "start= \"{0}\"  " wide //weight: 4
        $x_2_3 = "java-downloader.com/download.txt" wide //weight: 2
        $x_2_4 = {6d 65 74 68 6f 64 5f 32 00 66 6c 61 73 68 70 6c 61 79 65 72 5f 4c 6f 61 64}  //weight: 2, accuracy: High
        $x_2_5 = {66 6c 61 73 68 70 6c 61 79 65 72 5f 4c 6f 61 64 00 45 76 65 6e 74 41 72 67 73}  //weight: 2, accuracy: High
        $x_1_6 = "Windows\\svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

