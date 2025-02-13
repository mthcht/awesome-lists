rule Ransom_MSIL_LokiLocker_MK_2147808650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LokiLocker.MK!MTB"
        threat_id = "2147808650"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This file and all other files in your computer are encrypted by Loki locker" ascii //weight: 1
        $x_1_2 = "Please send us message to this e-mail" ascii //weight: 1
        $x_1_3 = "Write this ID in the title of your message" ascii //weight: 1
        $x_1_4 = "info.Loki" ascii //weight: 1
        $x_1_5 = "mshta.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LokiLocker_MA_2147851213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LokiLocker.MA!MTB"
        threat_id = "2147851213"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bf a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 e5 00 00 00 c5 00 00 00 d5}  //weight: 2, accuracy: High
        $x_2_2 = {06 7e c1 01 00 04 02 07 6f 8b 00 00 0a 7e 0a 01 00 04 07 7e 0a 01 00 04 8e 69 5d 91 61 28 7c 03 00 06 28 81 03 00 06 26 07 17 58 0b 07 02 6f 79 00 00 0a 32 c6}  //weight: 2, accuracy: High
        $x_1_3 = "98C69627-9ACD-49FE-B2A3-FB1DE0E07F73" ascii //weight: 1
        $x_1_4 = "EncryptDrives" ascii //weight: 1
        $x_1_5 = "LokiLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LokiLocker_ZA_2147851856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LokiLocker.ZA!MTB"
        threat_id = "2147851856"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" ascii //weight: 1
        $x_1_2 = "KillSwitch" ascii //weight: 1
        $x_1_3 = "Loki.Utilities.Interfaces" ascii //weight: 1
        $x_1_4 = "Loki.IO.Keyboards.Settings" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "Debugger Detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LokiLocker_ZB_2147851941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LokiLocker.ZB!MTB"
        threat_id = "2147851941"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "svchost.exe" ascii //weight: 10
        $x_10_2 = "Loki.Pinvoke.Native.IP_ADAPTER_INFO" ascii //weight: 10
        $x_10_3 = "BCryptEncrypt" ascii //weight: 10
        $x_1_4 = "StreamWriter" ascii //weight: 1
        $x_1_5 = "BinaryWriter" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "Loki.IO.Algorithms.Zip.FileInfo.ZipFileInfo" ascii //weight: 1
        $x_1_8 = "SHEmptyRecycleBin" ascii //weight: 1
        $x_1_9 = "encryptedPrivateKey" ascii //weight: 1
        $x_1_10 = "get_Is64BitOperatingSystem" ascii //weight: 1
        $x_1_11 = "<Loki>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

