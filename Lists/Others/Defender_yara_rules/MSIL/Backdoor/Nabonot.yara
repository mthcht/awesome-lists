rule Backdoor_MSIL_Nabonot_2147744166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nabonot!MTB"
        threat_id = "2147744166"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nabonot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 26 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 13 ?? 11 ?? 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {20 c4 8e fb 0e 13 ?? 11 ?? 72 ?? 00 00 70 6f ?? 00 00 0a 13 ?? 11 ?? 20 ?? ?? ?? ?? fe 02 13 ?? 20 ?? ?? ?? ?? 38 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

