rule TrojanDropper_Win64_ValleyRat_C_2147977199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/ValleyRat.C!MTB"
        threat_id = "2147977199"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 31 c0 41 81 c0 ?? ?? ?? ?? 45 31 c9 41 83 c9 40 48 ff 15 ?? ?? ?? ?? 48 85 c0 74 ?? 49 89 c4 4c 89 e7 48 8d 35 ?? ?? ?? ?? 49 89 f5 b9 ?? ?? ?? ?? fc f3 a4 41}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

