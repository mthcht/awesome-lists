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

