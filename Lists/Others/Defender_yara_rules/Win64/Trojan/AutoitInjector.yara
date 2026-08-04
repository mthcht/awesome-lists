rule Trojan_Win64_AutoitInjector_GVB_2147975144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AutoitInjector.GVB!MTB"
        threat_id = "2147975144"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AutoitInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8d 51 01 44 89 51 40 4d 63 c9 46 0f b6 4c 09 20 44 30 0c 02 48 83 c0 01 49 39 c0 0f 84 5a 01 00 00 44 8b 49 40 41 83 f9 20 75 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

