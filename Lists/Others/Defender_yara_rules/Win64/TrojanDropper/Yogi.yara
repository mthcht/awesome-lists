rule TrojanDropper_Win64_Yogi_MK_2147982679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Yogi.MK!MTB"
        threat_id = "2147982679"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {48 89 c2 41 0f b6 0c 41 83 e2 03 41 0f b6 14 17 31 d1 41 32 14 40 c1 e1 08 0f b6 d2 09 ca 66 89 14 ?? 48 83 c0 01 48 83 f8 1b}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

