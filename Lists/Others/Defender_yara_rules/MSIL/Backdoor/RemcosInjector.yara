rule Backdoor_MSIL_RemcosInjector_2147744532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RemcosInjector!MTB"
        threat_id = "2147744532"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemcosInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 16 00 00 0a 72 ?? ?? ?? 70 17 13 03 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 0d 00 00 00 20 02 00 00 00 13 03 20 ?? ?? ?? ?? 58}  //weight: 1, accuracy: Low
        $x_1_2 = {00 28 0f 00 00 06 28 17 00 00 0a a2 07 28 10 00 00 06 75 0e 00 00 01 0a d0 07 00 00 02 28 16 00 00 0a 72 ?? ?? ?? ?? 17 13 05 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 0d 00 00 00 20 02 00 00 00 13 05 20 ?? ?? ?? ?? 58}  //weight: 1, accuracy: Low
        $x_1_3 = {28 18 00 00 0a 28 19 00 00 0a 02 7b 0b 00 00 04 fe 06 1a 00 00 0a 73 11 00 00 06 0a 06 14 02 7b 0a 00 00 04 6f 12 00 00 06 26 28 1b 00 00 0a 28 1c 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_4 = {00 fe 0c 06 00 20 05 00 00 00 fe 01 39 1b 00 00 00 28 ?? 00 00 0a fe 09 00 00 6f ?? 00 00 0a fe 0e 01 00 20 06 00 00 00 fe 0e 06 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

