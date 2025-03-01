rule Trojan_MSIL_AgenTesla_MBFW_2147903706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBFW!MTB"
        threat_id = "2147903706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 9e 06 1d 06 1d 95 07 1d 95 61}  //weight: 1, accuracy: High
        $x_10_2 = {6f 00 76 00 72 00 66 00 6c 00 77 00 2e 00 65 00 78 00 65 00 00 00 00 00 22 00 01 00 01 00 50 00 72 00 6f}  //weight: 10, accuracy: High
        $x_10_3 = {45 43 58 65 76 00 41 74 74 72 69 62 75 74 65}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AgenTesla_MBYO_2147912556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBYO!MTB"
        threat_id = "2147912556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 06 08 6f ?? 00 00 0a 1f ?? 61 d2 9c 08 17 58 0c 08 06 6f ?? 00 00 0a 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AgenTesla_MBXL_2147917650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBXL!MTB"
        threat_id = "2147917650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e ?? 61 0c 08 0e ?? 59 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = "5AXBJZ78H857Y54D77XJP8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_AgenTesla_MBXN_2147917866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBXN!MTB"
        threat_id = "2147917866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "StealerLib.Browsers.CaptureBrowsers" wide //weight: 2
        $x_2_2 = "RecoverCredential" wide //weight: 2
        $x_2_3 = "smtp.gmail.com" wide //weight: 2
        $x_1_4 = "AES_Decryptor" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "Bitmap" ascii //weight: 1
        $x_1_7 = "Screenshot" ascii //weight: 1
        $x_1_8 = "SmtpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AgenTesla_MBXT_2147922342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgenTesla.MBXT!MTB"
        threat_id = "2147922342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgenTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 08 06 09 91 9c 06 09 11 [0-1] 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d}  //weight: 3, accuracy: Low
        $x_1_2 = {47 43 4d 2e 65 78 65 00 4d 6f 76 65 41 6e 67 6c 65 73 00 47 43 4d 00 52 65 73 6f 6c 76 65 72 00 56 69 72 74}  //weight: 1, accuracy: High
        $x_1_3 = "uiOAshyuxgYUA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

