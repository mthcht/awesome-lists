rule TrojanDownloader_MSIL_Jalapeno_AYB_2147926814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.AYB!MTB"
        threat_id = "2147926814"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bc.yui5.ru.com" wide //weight: 2
        $x_1_2 = "m8DCAB8" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Jalapeno_NIT_2147928359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.NIT!MTB"
        threat_id = "2147928359"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tempZipArchivePath" ascii //weight: 2
        $x_2_2 = "doSha256Check" ascii //weight: 2
        $x_2_3 = "shell\\open\\command" wide //weight: 2
        $x_1_4 = "NovaLauncher_ProcessedByFody" ascii //weight: 1
        $x_1_5 = "obj\\Release\\NovaLauncher.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Jalapeno_ALK_2147940693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.ALK!MTB"
        threat_id = "2147940693"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://edditdev.com" wide //weight: 2
        $x_2_2 = "discord.gg/mchsEXg2fc or dsc.gg/flexxcheats" wide //weight: 2
        $x_2_3 = "FLEXX_LOADER.Resources" wide //weight: 2
        $x_2_4 = "$c97ed578-ee4d-4ba7-8e6c-76d04c741a15" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Jalapeno_JKI_2147948436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.JKI!MTB"
        threat_id = "2147948436"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 1f 00 00 0a 25 6f 20 00 00 0a 72 61 00 00 70 72 77 00 00 70 6f 21 00 00 0a 25 72 6e 01 00 70 6f 22 00 00 0a 0a 6f 23 00 00 0a dd 03 00 00 00 26 de cc 02 06 28 01 00 00 2b 28 02 00 00 2b 28 26 00 00 0a 28 27 00 00 0a 02 73 28 00 00 0a 25}  //weight: 2, accuracy: High
        $x_2_2 = {02 7b 05 00 00 04 72 10 02 00 70 28 1e 00 00 0a 26 02 28 2a 00 00 0a 75 18 00 00 01 72 1e 02 00 70 6f 2b 00 00 0a 72 6a 02 00 70 1f 18 6f 2c 00 00 0a 0a 06 14 28 2d 00 00 0a 39 05 00 00 00 dd 1a 00 00 00 06 14 14 6f 2e 00 00 0a 26 dd 06 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Jalapeno_JLK_2147948437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Jalapeno.JLK!MTB"
        threat_id = "2147948437"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 1f 00 00 0a 25 6f 20 00 00 0a 72 61 00 00 70 72 77 00 00 70 6f 21 00 00 0a 25 72 6e 01 00 70 6f 22 00 00 0a 0a 6f 23 00 00 0a dd 03 00 00 00 26 de cc 02 06 28 01 00 00 2b 28 02 00 00 2b 28 26 00 00 0a 28 27 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = {02 7b 05 00 00 04 72 12 02 00 70 28 1e 00 00 0a 26 02 28 2a 00 00 0a 75 18 00 00 01 72 20 02 00 70 6f 2b 00 00 0a 72 6c 02 00 70 1f 18 6f 2c 00 00 0a 0a 06 14 28 2d 00 00 0a 39 05 00 00 00 dd 1a 00 00 00 06 14 14 6f 2e 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

