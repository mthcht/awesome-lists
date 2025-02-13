rule Trojan_MSIL_ZBot_RDA_2147846710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZBot.RDA!MTB"
        threat_id = "2147846710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8a192d26-6c0a-4b7d-b1dc-f307efb602e8" ascii //weight: 1
        $x_1_2 = "Hijack This" ascii //weight: 1
        $x_1_3 = "8Zht2lV2hXedhAiIuS" ascii //weight: 1
        $x_1_4 = "L58AdZeAo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

