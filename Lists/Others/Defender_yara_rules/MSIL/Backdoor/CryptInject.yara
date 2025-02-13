rule Backdoor_MSIL_CryptInject_2147742598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CryptInject!MTB"
        threat_id = "2147742598"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swety.Program" wide //weight: 1
        $x_1_2 = "aruncacheia.Properties.Resources" wide //weight: 1
        $x_1_3 = "AsyncCallback" ascii //weight: 1
        $x_1_4 = "__FixupData" ascii //weight: 1
        $x_1_5 = "DXOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_CryptInject_2147742598_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CryptInject!MTB"
        threat_id = "2147742598"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 04 00 00 0a 7e 0e 00 00 04 3a 11 00 00 00 14 fe 06 1c 00 00 06 73 05 00 00 0a 80 0e 00 00 04 7e 0e 00 00 04 28 01 00 00 2b 28 02 00 00 2b 73 08 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 04 7e 0f 00 00 04 3a 11 00 00 00 14 fe 06 ?? 00 00 06 73 ?? 00 00 0a 80 ?? 00 00 04 7e ?? 00 00 04 28 01 00 00 2b 28 02 00 00 2b 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {28 18 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 00 00 28 19 00 00 06 dd 06 00 00 00 26 dd 00 00 00 00 2a}  //weight: 1, accuracy: Low
        $x_1_4 = {fe 0e 00 00 fe 0c 00 00 20 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 00 00 28 ?? 00 00 06 dd 06 00 00 00 26 dd 00 00 00 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

