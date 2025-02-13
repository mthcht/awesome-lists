rule TrojanDropper_Win32_Lamberts_AS_2147751930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lamberts.AS!MTB"
        threat_id = "2147751930"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamberts"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 04 8b 01 69 c0 ?? ?? ?? ?? 05 39 30 00 00 89 01 c1 e8 10 25}  //weight: 1, accuracy: Low
        $x_1_2 = {32 04 3a 59 88 06 46 42 80 7d 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

