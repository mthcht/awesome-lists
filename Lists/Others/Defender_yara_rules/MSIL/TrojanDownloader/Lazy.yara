rule TrojanDownloader_MSIL_Lazy_RDF_2147890436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RDF!MTB"
        threat_id = "2147890436"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 08 00 00 0a 6f 09 00 00 0a 6f 0a 00 00 0a 73 0b 00 00 0a 20 a2 10 40 05 6f 0c 00 00 0a 13 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_RP_2147915041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.RP!MTB"
        threat_id = "2147915041"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\ALIENWARE\\Downloads\\Telegram Desktop\\ConsoleApp1\\ConsoleApp1\\obj\\Debug\\" ascii //weight: 10
        $x_1_2 = "del del.bat" wide //weight: 1
        $x_1_3 = "loader20" wide //weight: 1
        $x_1_4 = "U29mdHdhcmVJbnN0YWxsZXIq" wide //weight: 1
        $x_10_5 = "_Encrypted$" wide //weight: 10
        $x_1_6 = "SoftwareInstaller.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_NITA_2147921882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.NITA!MTB"
        threat_id = "2147921882"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 f9 01 00 70 0a 73 34 00 00 0a 0b 73 29 00 00 0a 25 72 e9 00 00 70 6f ?? 00 00 0a 00 25 72 a0 03 00 70 06 72 b6 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 72 65 00 00 70}  //weight: 2, accuracy: Low
        $x_2_2 = {73 12 00 00 06 0a 00 06 73 2e 00 00 0a 7d 0a 00 00 04 72 af 01 00 70 02 28 ?? 00 00 2b 06 fe 06 13 00 00 06 73 30 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 33 00 00 0a 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_NIT_2147952199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.NIT!MTB"
        threat_id = "2147952199"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 91 01 00 70 02 7b 01 00 00 04 02 7b 06 00 00 04 28 ?? 00 00 0a 8c 3a 00 00 01 28 ?? 00 00 0a 02 28 ?? 00 00 06 6f 39 00 00 0a de 0a 07 2c 06 07 6f 2b 00 00 0a dc 02 28 ?? 00 00 06 20 e8 03 00 00 28 ?? 00 00 0a 02 02 7b 05 00 00 04 72 ef 00 00 70 16 28 ?? 00 00 06 16}  //weight: 3, accuracy: Low
        $x_2_2 = {43 00 00 0a 02 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 0c 16 0d 2b 16 08 09 9a 13 04 02 7b 09 00 00 04 11 04 6f ?? 00 00 0a 09 17 58 0d 09 08 8e 69 32 e4 02 06 8e 69 7d 08 00 00 04 02 7b 0c 00 00 04 02 7b 08 00 00 04 6f ?? 00 00 0a 02 28 ?? 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_NQA_2147956856_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.NQA!MTB"
        threat_id = "2147956856"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DecodeBase64ToUrl" ascii //weight: 2
        $x_1_2 = "f4c6da9e-5be6-451b-857f-60f170b0aba7" ascii //weight: 1
        $x_1_3 = "ParseConfigFile" ascii //weight: 1
        $x_1_4 = "GetFileNameFromUrl" ascii //weight: 1
        $x_1_5 = "DecompressFile" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "base64Url" ascii //weight: 1
        $x_1_8 = "DownAp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Lazy_MK_2147959468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lazy.MK!MTB"
        threat_id = "2147959468"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {00 09 11 04 16 11 05 6f 0a 00 00 0a 00 00 08 11 04 16 11 04 8e 69 6f 0b 00 00 0a 25 13 05 16 fe 02 13 06 11 06 2d d9 09 6f 0c 00 00 0a 13 07 de 16}  //weight: 15, accuracy: High
        $x_10_2 = {00 08 03 16 03 8e 69 6f 0a 00 00 0a 00 00 de 0b 08 2c 07 08 6f 0d 00 00 0a 00 dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

