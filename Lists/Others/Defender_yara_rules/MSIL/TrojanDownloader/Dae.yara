rule TrojanDownloader_MSIL_Dae_A_2147731074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Dae.A!MTB"
        threat_id = "2147731074"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dae"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 01 00 00 06 26 07 14 28 02 00 00 06 26 dd 03 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Dae_YA_2147731702_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Dae.YA!MTB"
        threat_id = "2147731702"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dae"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 06 00 00 06 6f ?? 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 16 28 ?? 00 00 0a 20 ?? ?? 00 00 28 ?? 00 00 0a 6f ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 26 02 6f 19 00 00 06 16 6f ?? 00 00 0a 00 02 6f 1b 00 00 06 17 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Dae_YB_2147731773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Dae.YB!MTB"
        threat_id = "2147731773"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dae"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gxURiXjAT" wide //weight: 2
        $x_1_2 = "c:\\Users\\Mahmoud Kaibdaki\\Desktop\\" wide //weight: 1
        $x_1_3 = "https://pastebin.com" wide //weight: 1
        $x_2_4 = "FromBase64String" wide //weight: 2
        $x_2_5 = "get_ExecutablePath" wide //weight: 2
        $x_2_6 = "FileSplit" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

