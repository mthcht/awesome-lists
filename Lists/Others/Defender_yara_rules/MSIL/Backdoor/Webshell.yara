rule Backdoor_MSIL_Webshell_MBIH_2147889120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Webshell.MBIH!MTB"
        threat_id = "2147889120"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 00 69 00 66 00 6a 00 61 00 66 00 65 00 62 00 00 05 62 00 68 00 00 0d 64 00 65 00 65 00 61 00 63 00 61 00 00 05 6a 00 64 00 00 09 64 00 62 00 65 00 63 00 00 09 66}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 00 09 4c 00 6f 00 61 00 64 00 00 05 4c 00 59}  //weight: 1, accuracy: High
        $x_1_3 = "Gc/IeKxmF2bwTZ9zRX+4tosUjASi" wide //weight: 1
        $x_1_4 = "~/1234.aspx" wide //weight: 1
        $x_1_5 = "~/Service.aspx" wide //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
        $x_1_7 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Webshell_SPXF_2147911823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Webshell.SPXF!MTB"
        threat_id = "2147911823"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 73 1b 00 00 0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Webshell_MBXH_2147916534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Webshell.MBXH!MTB"
        threat_id = "2147916534"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6b 00 65 00 79 00 00 21 63 00 37 00 30 00 66 00 64 00 34 00 32 00 36 00 30 00 63 00 39 00 65 00 62 00 39 00 30 00 62}  //weight: 10, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Webshell_MBXT_2147922341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Webshell.MBXT!MTB"
        threat_id = "2147922341"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 00 70 00 70 00 5f 00 57 00 65 00 62 00 5f 00 [0-32] 2e 00 64 00 6c 00 6c}  //weight: 2, accuracy: Low
        $x_1_2 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 53 00 74 00 6f 00 72 00 65 00 4e 00 61 00 6d 00 65 00 7d 00 00 09 4c 00 6f 00 61 00 64 00 00 05 4c 00 59}  //weight: 1, accuracy: High
        $x_1_3 = "3c6e0b8a9c15224a" wide //weight: 1
        $x_1_4 = "FastObjectFactory_app_web_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

