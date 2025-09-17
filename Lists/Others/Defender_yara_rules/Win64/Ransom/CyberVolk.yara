rule Ransom_Win64_CyberVolk_PB_2147945444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CyberVolk.PB!MTB"
        threat_id = "2147945444"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CyberVolk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CyberVolk" ascii //weight: 1
        $x_3_2 = "FILES LOCKED BY CYBERVOLK" ascii //weight: 3
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_CyberVolk_PC_2147952431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CyberVolk.PC!MTB"
        threat_id = "2147952431"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CyberVolk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "#CyberVolk" ascii //weight: 3
        $x_1_2 = "DECRYPT_INSTRUCTIONS.txt" ascii //weight: 1
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

