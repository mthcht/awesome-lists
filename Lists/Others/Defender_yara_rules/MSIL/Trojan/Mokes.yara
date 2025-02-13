rule Trojan_MSIL_Mokes_B_2147783652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mokes.B!MTB"
        threat_id = "2147783652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 18 00 00 06 0a 06 02 28 05 00 00 06 7d 11 00 00 04 06 16 7d 12 00 00 04 06 16 7d 13 00 00 04 03 06 fe 06 19 00 00 06 73 22 00 00 0a 28 03 00 00 2b 2a}  //weight: 1, accuracy: High
        $x_1_2 = "AWkCZdaodw" ascii //weight: 1
        $x_1_3 = "XORIAIZCNIWw" ascii //weight: 1
        $x_1_4 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" ascii //weight: 1
        $x_1_5 = "DetectVirtualMachine" ascii //weight: 1
        $x_1_6 = "DetectSandboxie" ascii //weight: 1
        $x_1_7 = "DetectDebugger" ascii //weight: 1
        $x_1_8 = "CheckEmulator" ascii //weight: 1
        $x_1_9 = "RunOnStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mokes_AMO_2147844497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mokes.AMO!MTB"
        threat_id = "2147844497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {18 da 13 07 16 13 08 2b 1d 09 08 11 08 18 6f 4f 01 00 0a 1f 10 28 50 01 00 0a 6f 51 01 00 0a 00 11 08 18 d6 13 08 11 08 11 07 31 dd}  //weight: 2, accuracy: High
        $x_1_2 = "IntrastatPiese" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

