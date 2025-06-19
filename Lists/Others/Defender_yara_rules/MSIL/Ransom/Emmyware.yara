rule Ransom_MSIL_Emmyware_SK_2147944111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Emmyware.SK!MTB"
        threat_id = "2147944111"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Emmyware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TASKKILL /F /IM EXPLORER.EXE" ascii //weight: 1
        $x_1_2 = "Once you run this, you're fucked!" ascii //weight: 1
        $x_1_3 = "Trojan.Ransom.Emmyware" ascii //weight: 1
        $x_1_4 = "Emmyware.Properties.Resources" ascii //weight: 1
        $x_1_5 = "dc6qmok-7e7054dd-d7cf-415a-8c5e-938b1b999e46" ascii //weight: 1
        $x_1_6 = "WhatHappenLabel.Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

