rule TrojanSpy_Win64_Stealer_PAGM_2147937178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Stealer.PAGM!MTB"
        threat_id = "2147937178"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c8 4d 8b c2 80 e1 07 c0 e1 03 49 d3 e8 46 30 04 08 48 ff c0 48 83 f8}  //weight: 2, accuracy: High
        $x_2_2 = {8d 0c 1f 80 e1 07 c0 e1 03 49 8b d1 48 d3 ea 30 57 ff 40 0f b6 cf 41 2a c8 80 e1 07 c0 e1 03 49 8b d1 48 d3 ea 30 17 48 83 c7 02 48 8d 04 3b 48 83 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

