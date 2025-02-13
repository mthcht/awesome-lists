rule Trojan_Win32_Korad_A_2147655396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korad.A"
        threat_id = "2147655396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "== F.I.N.A.L.I.Z.A.T.I.O.N" ascii //weight: 1
        $x_1_2 = "mbAutoClickIsEnabled" ascii //weight: 1
        $x_1_3 = "giRandomLinkClickRateOnWeb1 = %d" ascii //weight: 1
        $x_1_4 = "Loop01[%d].sChkURL = %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Korad_D_2147687569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korad.D"
        threat_id = "2147687569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 45 b8 00 8d 71 01 8d 49 00 8a 11 41 84 d2 75 ?? 2b ce 8b f9 8d 75 b8 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 50 01 8a 08 40 84 c9 75 ?? 2b c2 50 8d 85 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? be 10 00 00 00 39 b5 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 49 00 8a 08 40 84 c9 75 ?? 8b 8d 9c 82 ff ff 2b c2 50 8d 85 c0 82 ff ff e8 ?? ?? ?? ?? 83 bd a0 ?? ?? ?? ?? 75 ?? 56 8b 35 ?? ?? ?? ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 25 73 [0-16] 25 30 32 64 25 30 32 64 25 30 32 64}  //weight: 1, accuracy: Low
        $x_2_5 = {3a 5c 70 72 6f 6a 65 63 74 5c 77 69 6e 33 32 5c 6d 6f 64 75 6c 65 5f 73 65 72 76 69 63 65 5c 52 65 6c 65 61 73 65 5c [0-12] 2e 70 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Korad_C_2147687570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korad.C"
        threat_id = "2147687570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 27 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 6a c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 65}  //weight: 5, accuracy: Low
        $x_5_2 = {27 6c 6a 6f c7 ?? ?? ?? ?? ?? 65 3e 35 00 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {0f b6 06 88 07 0f b6 4e 01 88 4f 01 0f b6 56 02 88 57 02 0f b6 46 03 88 47 03 0f b6 4e 04 8d 47 04 88 08 0f b6 56 05 88 57 05 0f b6 4e 06 88 4f 06}  //weight: 5, accuracy: High
        $x_5_4 = {0f b6 0e 88 4f fe 0f b6 56 01 8d 47 fe 88 57 ff 0f b6 4e 02 88 0f 0f b6 56 03 88 57 01 0f b6 56 04 8d 4f 02 88 11 0f b6 56 05 88 57 03 0f b6 56 06}  //weight: 5, accuracy: High
        $x_1_5 = {63 3a 5c 00 8b}  //weight: 1, accuracy: High
        $x_1_6 = {63 3a 5c 00 e8}  //weight: 1, accuracy: High
        $x_5_7 = {be 5a 00 00 00 f7 fe 8b 45 08 8d 34 01 0f be 04 33 bb 5a 00 00 00 41 8b fa 2b c7 83 c0 37 99 f7 fb 80 c2 23 3b 4d f8 88 16 7c ce}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

