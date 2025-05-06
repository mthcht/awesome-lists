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

