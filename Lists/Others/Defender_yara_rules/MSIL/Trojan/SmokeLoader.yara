rule Trojan_MSIL_Smokeloader_XT_2147829886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Smokeloader.XT!MTB"
        threat_id = "2147829886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1d 2d 2e 26 06 08 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de 11 0c 2b d0}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Smokeloader_JN_2147830752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Smokeloader.JN!MTB"
        threat_id = "2147830752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 1d 2c de 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 08 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "Kjysuwjrnwh" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Cgpzvrgxodwcymxlrtzbois" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Smokeloader_AMBA_2147893944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Smokeloader.AMBA!MTB"
        threat_id = "2147893944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed}  //weight: 5, accuracy: High
        $x_5_2 = {54 d5 29 5c 70 71 7b 28 78 7a 77 6f 7a 69 75 28 6b 69 76 76 77 7c 28 6a 6d 28 7a 7d 76 28 71 76 28 4c 57 5b 28 75 77 6c 6d 36}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

