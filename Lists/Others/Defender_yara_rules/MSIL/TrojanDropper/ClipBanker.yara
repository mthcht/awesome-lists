rule TrojanDropper_MSIL_ClipBanker_A_2147830886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/ClipBanker.A!MTB"
        threat_id = "2147830886"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 9a 14 14 6f ?? 00 00 0a 74 ?? 00 00 01 0a de}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 0b 07 2a}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 04 0b 07 2a}  //weight: 2, accuracy: High
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "SecurityProtocol" ascii //weight: 1
        $x_1_7 = "ResourceManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

