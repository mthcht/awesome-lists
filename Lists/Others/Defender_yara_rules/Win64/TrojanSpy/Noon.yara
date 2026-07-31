rule TrojanSpy_Win64_Noon_SK_2147975013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Noon.SK!MTB"
        threat_id = "2147975013"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Noon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 51 01 0f b6 09 33 c1 c1 c0 0d 69 c0 a9 d2 b7 c5 8b c8 c1 e9 0f 33 c1 80 3a 00 48 8b ca 75 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

