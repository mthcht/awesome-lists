rule TrojanDropper_Win64_KillAV_GB_2147978415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/KillAV.GB!MTB"
        threat_id = "2147978415"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "KillAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 ba 75 65 73 70 65 6d 6f 73 48 31 c2 49 b8 6d 6f 64 6e 61 72 6f 64 49 31 c8 49 b9 61 72 65 6e 65 67 79 6c 49 31 c1 49 ba 73 65 74 79 62 64 65 74 49 31 ca 48 89 54 24 ?? 4c 89 4c 24 ?? 4c 89 44 24 ?? 4c 89 54 24 ?? 48 89 44 24 ?? 48 89 4c 24 ?? 66 0f ef}  //weight: 3, accuracy: Low
        $x_1_2 = "truckersmp_dlc_bypass" ascii //weight: 1
        $x_1_3 = {49 b8 75 65 73 70 65 6d 6f 73 48 89 c2 4c 31 c2 49 b9 6d 6f 64 6e 61 72 6f 64 49 89 c8 4d 31 c8 49 ba 61 72 65 6e 65 67 79 6c 49 89 c1 4d 31 d1 49 bb 73 65 74 79 62 64 65 74 49 89 ca 4d 31 da 48 89 54 24 38 4c 89 4c 24 40 4c 89 44 24 48 4c 89 54 24 50 48 89 44 24 58 48 89 4c 24 60 0f 57 c0}  //weight: 1, accuracy: High
        $x_1_4 = "core_ets2mp" ascii //weight: 1
        $x_1_5 = "dstorage.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

