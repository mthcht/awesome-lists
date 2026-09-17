rule TrojanDropper_Win64_KillAv_PB_2147978380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/KillAv.PB!MTB"
        threat_id = "2147978380"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ba 75 65 73 70 65 6d 6f 73 48 31 c2 49 b8 6d 6f 64 6e 61 72 6f 64 49 31 c8 49 b9 61 72 65 6e 65 67 79 6c 49 31 c1 49 ba 73 65 74 79 62 64 65 74 49 31 ca 48 89 54 24 ?? 4c 89 4c 24 ?? 4c 89 44 24 ?? 4c 89 54 24 ?? 48 89 44 24 ?? 48 89 4c 24 ?? 66 0f ef c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

