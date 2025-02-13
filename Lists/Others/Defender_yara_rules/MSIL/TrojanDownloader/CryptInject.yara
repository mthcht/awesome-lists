rule TrojanDownloader_MSIL_CryptInject_BA_2147761868_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CryptInject.BA!MTB"
        threat_id = "2147761868"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "costura.system.inf.dll.zip" wide //weight: 1
        $x_1_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00 45 6e 64 73 57 69 74 68 00 47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d 00 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CryptInject_BC_2147784000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CryptInject.BC!MTB"
        threat_id = "2147784000"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 09 02 00 61 d1 9d fe 0c 00 00 20 cc ac 85 bb 20 02 00 00 00 63 20 07 6e 99 06 58 66 20 02 00 00 00 62 20 1c 9b ff 1b 59 66 20 06 00 eb f1 59 59 25 fe 0e 00 00 20 19 a8 be fa 20 19 a8 be fa 59}  //weight: 1, accuracy: High
        $x_1_2 = "e_magic" ascii //weight: 1
        $x_1_3 = "SizeOfImage" ascii //weight: 1
        $x_1_4 = "OptionalHeader" ascii //weight: 1
        $x_1_5 = "e_lfanew" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CryptInject_MBM_2147837919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CryptInject.MBM!MTB"
        threat_id = "2147837919"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 8e 69 5d 91 02 7b ?? 00 00 04 07 91 61 d2 6f ?? 00 00 0a 17 2c b0 07 17 25 2c 0e}  //weight: 1, accuracy: Low
        $x_1_2 = "Zxchaqolkp.Fhxnska" wide //weight: 1
        $x_1_3 = "Viwsrgxzev" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CryptInject_AC_2147838878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CryptInject.AC!MTB"
        threat_id = "2147838878"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 05 9a 13 06 02 fe 06 1c 00 00 06 73 58 00 00 0a 73 59 00 00 0a 13 07 11 07 06 72 45 02 00 70 11 06 28 5a 00 00 0a 6f 5b 00 00 0a 00 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d bc}  //weight: 2, accuracy: High
        $x_1_2 = "avocado.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

