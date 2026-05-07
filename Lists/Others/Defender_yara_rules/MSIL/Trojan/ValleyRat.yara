rule Trojan_MSIL_ValleyRat_GL_2147960023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ValleyRat.GL!MTB"
        threat_id = "2147960023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{7A7A2B97-E559-4A51-8D76-EEE405F0C793}" ascii //weight: 2
        $x_1_2 = "Microsoft.CodeAnalysis" ascii //weight: 1
        $x_1_3 = "WritePacked" ascii //weight: 1
        $x_1_4 = "HasCallbacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ValleyRat_BA_2147968609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ValleyRat.BA!MTB"
        threat_id = "2147968609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 16 73 0d 00 00 0a 13 07 73 0e 00 00 0a 13 08 20 00 40 00 00 8d 0f 00 00 01 13 09 2b 0c 11 08 11 09 16 11 0a ?? ?? 00 00 0a 11 07 11 09 16 11 09 8e 69 ?? ?? 00 00 0a 25 13 0a 16 30 e0 11 08 ?? ?? 00 00 0a 13 05 de 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

