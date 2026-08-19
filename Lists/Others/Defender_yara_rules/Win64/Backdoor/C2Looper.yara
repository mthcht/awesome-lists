rule Backdoor_Win64_C2Looper_CB_2147976424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/C2Looper.CB!MTB"
        threat_id = "2147976424"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "C2Looper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 89 e8 83 e0 07 0f b6 6c 04 ?? 45 31 e4 42 32 2c 2b 41 0f 98 c4 49 ff c4 48 8b 4c 24 ?? 4c 29 f9 4c 89 f8 49 39 cc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

