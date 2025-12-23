rule TrojanDropper_Win64_Fragtor_ARAX_2147959972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Fragtor.ARAX!MTB"
        threat_id = "2147959972"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Fragtor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 2c 07 00 00 48 98 0f b6 84 05 c8 04 00 00 83 f0 7f 8b 95 2c 07 00 00 48 63 d2 88 84 15 c8 04 00 00 83 85 2c 07 00 00 01 83 bd 2c 07 00 00 07 7e cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

