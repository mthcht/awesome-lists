rule PWS_MSIL_Hawkeye_ACM_2147833018_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Hawkeye.ACM!MTB"
        threat_id = "2147833018"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 88 00 00 00 91 1f 79 59 2b ed 11 04 1f 7e 91 1c 5b 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Hawkeye_ADZE_2147833957_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Hawkeye.ADZE!MTB"
        threat_id = "2147833957"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 91 1f 1f 31 20 07 08 91 1f 7f 2f 19 07 08 13 04 11 04 07 11 04 91 08 1f 1f 5d 1f 10 d6 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Hawkeye_ADIK_2147834055_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Hawkeye.ADIK!MTB"
        threat_id = "2147834055"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 06 9a 0b 06 07 8e 69 6a 58 0a 11 06 17 58 13 06 11 06 11 05 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Hawkeye_ACXK_2147834662_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Hawkeye.ACXK!MTB"
        threat_id = "2147834662"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 02 8e b7 18 da 13 06 13 05 2b 65 02 11 05 91 0b 02 11 05 17 d6 91 0d 18 09 d8 03 da 07 da 13 04 03 07 da 09 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Hawkeye_AKVV_2147839134_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Hawkeye.AKVV!MTB"
        threat_id = "2147839134"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 0a 06 8e 69 8d 22 00 00 01 0b 16 0c 2b 0a 07 08 06 08 91 9d 08 17 58 0c 08 07 8e 69 32 f0}  //weight: 2, accuracy: High
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

