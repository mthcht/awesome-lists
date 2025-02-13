rule Backdoor_MSIL_CinaRAT_A_2147837688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/CinaRAT.A!MTB"
        threat_id = "2147837688"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CinaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 28 ?? 00 00 06 6f ?? ?? 00 06 6f ?? 00 00 06 16 9a a2 25 17 28 ?? 00 00 06 6f ?? ?? 00 06 6f ?? 00 00 06 17 9a a2 25 18 72}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 1b 9a 0a 06 72 ?? ?? ?? 70 18 17 8d ?? 00 00 01 25 16 72 ?? ?? ?? 70 a2 28}  //weight: 2, accuracy: Low
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

