rule TrojanDownloader_MSIL_Tedy_NE_2147830481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tedy.NE!MTB"
        threat_id = "2147830481"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 14 00 00 0a 25 72 01 00 00 70 6f 15 00 00 0a 25 17 6f 16 00 00 0a 25 72 17 00 00 70 6f 17 00 00 0a 28 18 00 00 0a 26 2a}  //weight: 2, accuracy: High
        $x_2_2 = "ETH COINt.WTF COINlIOSNT" wide //weight: 2
        $x_2_3 = "$TRUMP" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tedy_SXA_2147969026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tedy.SXA!MTB"
        threat_id = "2147969026"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "<DropEncryptedStartupScript>" ascii //weight: 30
        $x_20_2 = "<GetDesiredPayloadVersionAsync>" ascii //weight: 20
        $x_10_3 = "Global\\ProtectEvaluate_{B4E5F1A2-3D8C-4E9F-9A1B-2C3D4E5F6A7B}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Tedy_MQR_2147971563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tedy.MQR!MTB"
        threat_id = "2147971563"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0a 02 8e 69 8d 06 00 00 01 0b 16 0c 2b 0d 07 08 02 08 91 06 61 d2 9c 08 17 58 0c 08 02 8e 69 32 ed 28 05 00 00 0a 07 6f 06 00 00 0a 2a}  //weight: 7, accuracy: High
        $x_1_2 = "scloader_debug.txt" wide //weight: 1
        $x_1_3 = "Execute como Administrador" wide //weight: 1
        $x_1_4 = "MSI:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

