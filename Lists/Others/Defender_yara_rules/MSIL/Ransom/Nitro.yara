rule Ransom_MSIL_Nitro_DA_2147780451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nitro.DA!MTB"
        threat_id = "2147780451"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nitro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NitroRansomware.Properties.Resources" ascii //weight: 1
        $x_1_2 = "file:///" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "Base64String" ascii //weight: 1
        $x_1_5 = "Debugger Detected" ascii //weight: 1
        $x_1_6 = "is tampered" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Nitro_PAA_2147794172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nitro.PAA!MTB"
        threat_id = "2147794172"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nitro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows defender/ any antivirus is off" ascii //weight: 1
        $x_1_2 = "important documents have been locked" ascii //weight: 1
        $x_1_3 = "NitroRansomware.Resources" ascii //weight: 1
        $x_1_4 = "FormUrlEncodedContent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Nitro_MVT_2147900599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nitro.MVT!MTB"
        threat_id = "2147900599"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nitro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NitroRansomware.exe" ascii //weight: 5
        $x_1_2 = "Why are black black" ascii //weight: 1
        $x_1_3 = "d5e87439-21e6-4567-a877-6ad9bee00dc9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

