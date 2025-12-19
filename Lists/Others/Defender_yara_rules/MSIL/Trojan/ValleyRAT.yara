rule Trojan_MSIL_ValleyRAT_GZD_2147959789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ValleyRAT.GZD!MTB"
        threat_id = "2147959789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6B524511-479E-BC5E-9E11-9EDD262AE2CE" ascii //weight: 2
        $x_1_2 = "Microsoft.CodeAnalysis" ascii //weight: 1
        $x_1_3 = "WritePacked" ascii //weight: 1
        $x_1_4 = "HasCallbacks" ascii //weight: 1
        $x_1_5 = "ProtoBuf.Serializers.IProtoTypeSerializer.HasCallbacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

