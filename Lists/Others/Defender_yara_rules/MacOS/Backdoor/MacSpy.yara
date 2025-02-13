rule Backdoor_MacOS_MacSpy_B_2147798311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/MacSpy.B!MTB"
        threat_id = "2147798311"
        type = "Backdoor"
        platform = "MacOS: "
        family = "MacSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 30 00 00 00 ba 07 00 00 00 e8 68 bc f7 ff 49 89 c4 0f 28 05 9e ce 33 00 41 0f 11 44 24 10 41 c7 44 24 20 01 00 00 00 48 b8 0e 00 00 00 01 00 00 00 49 89 44 24 24 e8 e5 b9 33 00 41 89 44 24 2c 48 c7 45 d8 88 02 00 00 4c 89 e7 e8 36 b9 f7 ff a8 01 74 4f 49 8b 74 24 10 89 f0 48 39 c6 75 7e 49 8d 7c 24 20 48 8d 95 50 fd ff ff 48 8d 4d d8 45 31 c0 45 31 c9 e8 3f bc 33 00 bb 00 08 00 00 23 9d 70 fd ff ff 4c 89 e7 e8 a8 f7 32 00 c1 eb 0b 89 d8 48 81 c4 90 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 31 09 00 76 32 09 00 76 33 09 00 69 31 09 00 69 32 09 00 69 33 09 00 69 34 09 00 66 31 09 00 66 32 09 00 66 33 09 00 66 34 09 00 74 63 3a 00 74 66 3a 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 89 f7 e8 47 48 3c 00 66 0f 6f 4d b0 66 0f 70 c1 4e 66 48 0f 7e c0 4c 85 e0 74 45 66 0f 7f 4d c0 4c 89 7d d0 be 02 00 00 00 4c 89 ff e8 1d 47 3c 00 48 8d 3d 9a 2a 3e 00 48 8d 4d c0 be 01 00 00 00 31 d2 e8 36 e0 2e 00 66 0f 6f 45 c0 66 0f 7f 45 b0 4c 8b 75 d0 4c 89 ff e8 f0 47 3c 00 eb 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

