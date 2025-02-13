rule TrojanDownloader_MSIL_Androm_SIB_2147798220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Androm.SIB!MTB"
        threat_id = "2147798220"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 6a 0a 16 0b 2b ?? 02 6f ?? ?? ?? ?? 0c 06 08 d2 6e 1e 07 5a 1f ?? 5f 62 60 0a 07 17 58 0b 07 1e 32 ?? 06}  //weight: 10, accuracy: Low
        $x_1_2 = "ALARIC Loader.exe" ascii //weight: 1
        $x_1_3 = {73 00 74 00 75 00 62 00 5f 00 [0-16] 2e 00 [0-16] 72 00 73 00 72 00 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 75 62 5f [0-16] 2e [0-16] 72 73 72 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Androm_CXD_2147842144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Androm.CXD!MTB"
        threat_id = "2147842144"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 1a 00 00 0a 13 04 de 7c 07 2b c1 73 ?? ?? ?? ?? 2b c1 73 ?? ?? ?? ?? 2b bc 0d 2b}  //weight: 5, accuracy: Low
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 39 00 33 00 2e 00 32 00 30 00 31 00 2e 00 36 00 32 00 2f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Androm_AND_2147896989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Androm.AND!MTB"
        threat_id = "2147896989"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 06 07 6f ?? 00 00 0a 72 ?? 01 00 70 28 ?? 00 00 0a 11 06 08 09 6f ?? 00 00 0a 72 ?? 01 00 70 28 ?? 00 00 0a 11 06 11 04 11 05}  //weight: 2, accuracy: Low
        $x_1_2 = "C:\\Users\\Public\\229cs.ps1" wide //weight: 1
        $x_1_3 = "PowerShell command executed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

