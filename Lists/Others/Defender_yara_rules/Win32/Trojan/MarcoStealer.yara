rule Trojan_Win32_MarcoStealer_AMC_2147965614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MarcoStealer.AMC!MTB"
        threat_id = "2147965614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MarcoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 47 04 88 47 14 32 57 05 88 57 15 44 32 57 06 44 88 57 16 41 32 ca 44 32 47 07 44 88 47 17 41 32 d8 32 47 08 44 32 d8 88 47 18 32 57 09 44 32 ca 88 57 19 88 4f 1a 88 5f 1b 44 88 5f 1c 44 88 4f 1d}  //weight: 1, accuracy: High
        $x_2_2 = "217.156.50.228" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

