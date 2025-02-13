rule TrojanDownloader_MSIL_ArtemisLoader_B_2147831384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ArtemisLoader.B!MTB"
        threat_id = "2147831384"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2b c6 28 ?? 00 00 06 2b c1 6f ?? 00 00 0a 2b bc 6f ?? 00 00 0a 2b b7 28 ?? 00 00 2b 2b d1 28 ?? 00 00 2b 2b cc 6f ?? 00 00 0a 2b c8 0a 2b c7 06 2b c8}  //weight: 2, accuracy: Low
        $x_2_2 = {16 2d 08 08 6f ?? 00 00 0a 13 04 de 33 07 2b cc 73 ?? 00 00 0a 2b c8 73 ?? 00 00 0a 2b c3 0d 2b c2}  //weight: 2, accuracy: Low
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ArtemisLoader_ART_2147832706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ArtemisLoader.ART!MTB"
        threat_id = "2147832706"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e 69 5d 91 02 7b ?? ?? ?? 04 07 91 61 d2 6f ?? ?? ?? 0a 07 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "dweb.link" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ArtemisLoader_SRP_2147836051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ArtemisLoader.SRP!MTB"
        threat_id = "2147836051"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 11 05 8f 85 00 00 01 72 f4 04 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 11 05 17 d6 13 05 11 05 11 04 31 db}  //weight: 5, accuracy: Low
        $x_2_2 = "Place_Search.pdb" ascii //weight: 2
        $x_2_3 = "onlyone_updater.exe" wide //weight: 2
        $x_1_4 = "upadte.dll" wide //weight: 1
        $x_1_5 = "Place_Search.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_ArtemisLoader_RDC_2147845148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ArtemisLoader.RDC!MTB"
        threat_id = "2147845148"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aee520cb-9d86-4742-ba0b-78ec1e132ac4" ascii //weight: 1
        $x_1_2 = "//puresvr01.sytes.net/dashboard/panel/uploads/Afxufottv.bmp" wide //weight: 1
        $x_1_3 = "Pcxzbt.Kjsapknlehhacruneupcu" wide //weight: 1
        $x_1_4 = "Yewkycsornxiq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

