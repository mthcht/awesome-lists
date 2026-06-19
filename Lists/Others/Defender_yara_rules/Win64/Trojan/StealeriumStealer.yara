rule Trojan_Win64_StealeriumStealer_ASE_2147971968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealeriumStealer.ASE!MTB"
        threat_id = "2147971968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealeriumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 29 f8 83 f8 10 0f 43 c5 44 39 fb 74 23 83 f8 01 89 c1 83 d1 00 44 89 fa 45 31 c0 46 8a 4c 04 70 46 8d 14 02 47 30 0c 16 49 ff c0 4c 39 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

