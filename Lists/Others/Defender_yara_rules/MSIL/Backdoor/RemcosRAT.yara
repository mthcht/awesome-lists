rule Backdoor_MSIL_RemcosRAT_A_2147837687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RemcosRAT.A!MTB"
        threat_id = "2147837687"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {9a 1f 10 28}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 01 25 16 1f 27 9d 6f}  //weight: 2, accuracy: High
        $x_2_3 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

