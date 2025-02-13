rule Backdoor_MSIL_DCRAT_AA_2147910267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRAT.AA!MTB"
        threat_id = "2147910267"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {00 00 72 85 12 00 70 28 86 01 00 06 02 72 ?? ?? ?? 70 6f c0 00 00 0a 28 04 00 00 2b 28 83 01 00 06 28 b7 01 00 06 28 85 01 00 06 28 07 00 00 2b 0a 06 72 ?? ?? ?? 70 6f 04 01 00 0a 74 1c 00 00 1b 0b 00 06 72 6d 09 00 70 6f 04 01 00 0a 74 60 00 00 01 28 85 01 00 06 28 0d 00 00 2b 80 a6 00 00 04 00 dd 08 00 00 00 26 00 00 dd 00 00 00 00}  //weight: 100, accuracy: Low
        $x_100_3 = {11 06 11 07 9a 13 08 00 11 08 6f 9e 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 a6 07 00 70 28 97 00 00 0a 6f 99 00 00 0a 13 09 11 09 39 b3 05 00 00 00 7e a7 00 00 04 13 0a 16 13 0b 11 0a 12 0b 28 7f 01 00 0a 00 73 07 01 00 06 13 0c 00 11 0c 06 11 08 6f 80 01 00 0a 6f 30 01 00 0a 7d b0 00 00 04 7e a7 00 00 04 06 6f 7c 01 00 0a 11 0c 7b b0 00 00 04 6f 81 01 00 0a 00 00 11 08 6f 31 01 00 0a 13 0d 16 13 0e 38 39 05 00 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

