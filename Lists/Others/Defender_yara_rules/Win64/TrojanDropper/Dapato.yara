rule TrojanDropper_Win64_Dapato_AH_2147962735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Dapato.AH!MTB"
        threat_id = "2147962735"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = "main.rerunElevated" ascii //weight: 40
        $x_30_2 = "run payload:" ascii //weight: 30
        $x_20_3 = {48 89 5c 24 38 48 89 44 24 50 48 8d ?? ?? ?? ?? 00 bb 18 00 00 00 31 c9 31 ff 48 89 fe 0f 1f 44 00 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

