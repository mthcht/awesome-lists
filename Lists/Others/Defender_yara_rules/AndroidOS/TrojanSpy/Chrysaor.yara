rule TrojanSpy_AndroidOS_Chrysaor_B_2147815438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Chrysaor.B!MTB"
        threat_id = "2147815438"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Chrysaor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 a0 e3 c0 30 0b e5 00 01 1b e5 b8 34 9f e5 03 30 8f e0 03 10 a0 e1 b0 34 9f e5 03 30 94 e7 03 20 a0 e1 cc ?? ?? ?? 00 30 a0 e1 c8 30 0b e5 00 01 1b e5 98 34 9f e5 03 30 8f e0 03 10 a0 e1 ?? 34 9f e5 03 30 94 e7 03 20 a0 e1 c2 ?? ?? ?? 00 30 a0 e1 c4 30 0b e5 00 01 1b e5 78 34 9f e5 03 30 8f e0 03 10 a0 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {16 4c 16 4a 17 4d 7c 44 7a 44 03 20 21 1c 7d 44 ff ?? ?? ?? 6b 68 01 2b 17 d0 12 4a 01 23 6b 60 7a 44 21 1c 03 20 ff ?? ?? ?? 0f 48 10 49 10 4a 78 44 79 44 7a 44 2b 1c ff ?? ?? ?? 0e 4a 03 20 21 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

