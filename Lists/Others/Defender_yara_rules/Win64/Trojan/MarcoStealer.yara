rule Trojan_Win64_MarcoStealer_AMR_2147965622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MarcoStealer.AMR!MTB"
        threat_id = "2147965622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MarcoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 56 f1 88 56 01 32 5e f2 88 5e 02 44 32 4e f3 44 88 4e 03 32 46 f4 88 46 04 32 56 f5 88 56 05 32 5e f6 88 5e 06 32 d9 44 32 4e f7 44 88 4e 07 44 32 cf 32 46 f8 88 46 08 41 32 c3 32 56 f9 88 56 09 41 32 d2 88 56 0d 88 5e 0a 44 88 4e 0b 88 46 0c}  //weight: 2, accuracy: High
        $x_1_2 = "TCXMOUCYRGATNOROO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

