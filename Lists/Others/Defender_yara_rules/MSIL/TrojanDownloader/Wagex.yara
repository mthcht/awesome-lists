rule TrojanDownloader_MSIL_Wagex_ABJI_2147839199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.ABJI!MTB"
        threat_id = "2147839199"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 05 18 2c f6 18 2c 2b 07 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 11 06 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a de 0c 11 06 2c 07 11 06 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 13 07 16 2d bd}  //weight: 4, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wagex_AW_2147842020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.AW!MTB"
        threat_id = "2147842020"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 18 2d 03 26 2b 1b 0a 2b fb 00 02 72 01 00 00 70 28 ?? ?? ?? 06 1a 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wagex_AW_2147842020_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.AW!MTB"
        threat_id = "2147842020"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 18 2c bd 11 04 15 2c da 17 58 13 04 11 04 07 8e 16 2d 01 69 32 d6 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wagex_AWX_2147842021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.AWX!MTB"
        threat_id = "2147842021"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 0b 2b 0c 00 06 02 07 91 6f 2d 00 00 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wagex_MBDF_2147845447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.MBDF!MTB"
        threat_id = "2147845447"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 08 16 19 2d 06 17 2c 6a 26 2b 6d 16 2d 6b 2b 76 2b f7 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 2b 28 1e 2d 1b 26 2b 29 2b 2e 2b 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Wagex_ABHX_2147896502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Wagex.ABHX!MTB"
        threat_id = "2147896502"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 29 00 00 0a 72 11 00 00 70 28 2a 00 00 0a 0a 06 28 06 00 00 06 0b 07 28 2b 00 00 0a 0c 08 72 23 00 00 70 6f 2c 00 00 0a 6f 2d 00 00 0a 0d 09 28 2e 00 00 0a 13 04 11 04 16 6f 2f 00 00 0a 74 1b 00 00 01 13 05 11 05 18 6f 2f 00 00 0a 74 1b 00 00 01 13 06 16 13 07 38 fd 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "WorldCupTwo.Properties.Resources" wide //weight: 1
        $x_1_3 = "WorldCupTwo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

