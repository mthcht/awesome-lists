rule Backdoor_Win64_Bladabindi_PGC_2147960305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bladabindi.PGC!MTB"
        threat_id = "2147960305"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f3 42 0f 6f 44 00 e0 48 8d 40 40 83 c2 40 66 0f 6f ca 0f 57 c2 f3 0f 7f 40 a0 f3 0f 6f 44 01 a0 0f 57 c2 f3 0f 7f 40 b0 f3 42 0f 6f 44 00 c0 0f 57 c8 f3 0f 6f 44 01 c0 f3 0f 7f 48 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

