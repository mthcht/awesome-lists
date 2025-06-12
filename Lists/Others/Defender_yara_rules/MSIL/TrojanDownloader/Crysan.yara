rule TrojanDownloader_MSIL_Crysan_IFL_2147819212_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Crysan.IFL!MTB"
        threat_id = "2147819212"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "194.26.192.131" wide //weight: 1
        $x_1_2 = "tutorial.gya" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Crysan_RS_2147839938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Crysan.RS!MTB"
        threat_id = "2147839938"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 30 00 00 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Crysan_RDA_2147841235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Crysan.RDA!MTB"
        threat_id = "2147841235"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "16ccf950-d10f-4d64-91e0-ee460be4f1f1" ascii //weight: 1
        $x_1_2 = "BernySpoofer" ascii //weight: 1
        $x_1_3 = "Stoneless-2457" ascii //weight: 1
        $x_2_4 = {00 28 43 00 00 0a 03 ?? ?? ?? ?? ?? 16 1f 20 6f 40 00 00 0a 6f 44 00 00 0a 0a 28 43 00 00 0a 04 ?? ?? ?? ?? ?? 16 1f 10 6f 40 00 00 0a 6f 44 00 00 0a 0b 02 06 07 ?? ?? ?? ?? ?? 0c 2b 00 08 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Crysan_ACY_2147943529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Crysan.ACY!MTB"
        threat_id = "2147943529"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 04 16 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 39 ?? 00 00 00 0e 04 04 25 3a ?? 00 00 00 26 72 ?? 00 00 70 51 16 0b}  //weight: 2, accuracy: Low
        $x_1_2 = {0a 0b 07 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0a}  //weight: 1, accuracy: Low
        $x_5_3 = "filecrumb.nl/panel/uploads/Aepnziwy.wav" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

