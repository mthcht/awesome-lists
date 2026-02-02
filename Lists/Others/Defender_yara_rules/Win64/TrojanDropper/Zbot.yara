rule TrojanDropper_Win64_Zbot_ARA_2147962152_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Zbot.ARA!MTB"
        threat_id = "2147962152"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 1c 07 00 00 48 98 0f b6 84 05 c8 04 00 00 83 f0 7f 89 c2 8b 85 1c 07 00 00 48 98 88 94 05 c8 04 00 00 83 85 1c 07 00 00 01 83 bd 1c 07 00 00 07 7e cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

