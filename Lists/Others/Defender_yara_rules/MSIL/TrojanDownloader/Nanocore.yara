rule TrojanDownloader_MSIL_Nanocore_SA_2147753095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nanocore.SA!MTB"
        threat_id = "2147753095"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\name.exe" wide //weight: 2
        $x_2_2 = "%appdata%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Arablifec.exe" wide //weight: 2
        $x_1_3 = "Information not reported for security reasons" wide //weight: 1
        $x_2_4 = {46 00 6f 00 6c 00 64 00 65 00 72 00 4e 00 5c 00 78 00 39 00 30 00 02 00 07 00 2e 00 62 00 61 00 74 00}  //weight: 2, accuracy: High
        $x_2_5 = "Arablifec\\mata2.bat" wide //weight: 2
        $x_2_6 = "folder#\\#rundll32.exe#" wide //weight: 2
        $x_2_7 = "svhost.exe" wide //weight: 2
        $x_1_8 = "RegAsm.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Nanocore_PA1_2147819050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nanocore.PA1!MTB"
        threat_id = "2147819050"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tac.fmop.a//:sptth" ascii //weight: 2
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "ReverseText" ascii //weight: 1
        $x_1_4 = "powershell.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Nanocore_ABH_2147831440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nanocore.ABH!MTB"
        threat_id = "2147831440"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 06 6f ?? ?? ?? 0a 13 04 de 4b}  //weight: 3, accuracy: Low
        $x_1_2 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

