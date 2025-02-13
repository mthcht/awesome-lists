rule Backdoor_MSIL_NetwireRAT_A_2147846838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NetwireRAT.A!MTB"
        threat_id = "2147846838"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetwireRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 02 a2 28}  //weight: 2, accuracy: Low
        $x_2_2 = {07 08 09 28}  //weight: 2, accuracy: High
        $x_2_3 = {00 06 d2 06 28}  //weight: 2, accuracy: High
        $x_2_4 = {59 1c 58 0d}  //weight: 2, accuracy: High
        $x_2_5 = {06 17 58 0a}  //weight: 2, accuracy: High
        $x_2_6 = {08 1a 59 1b 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

