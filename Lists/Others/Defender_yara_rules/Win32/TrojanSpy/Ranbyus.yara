rule TrojanSpy_Win32_Ranbyus_A_2147621587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ranbyus.A"
        threat_id = "2147621587"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c3 ff fb ff ff c1 eb 0a 43 8b c3 69 c0 00 fc ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {eb 02 d1 e8 4a 75 ee 89 04 8d 05 00 35}  //weight: 2, accuracy: Low
        $x_1_3 = ".iBank*" ascii //weight: 1
        $x_1_4 = "<form\\saction" ascii //weight: 1
        $x_1_5 = "prfx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ranbyus_C_2147645265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ranbyus.C"
        threat_id = "2147645265"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "https:\\/\\/ibank.alfabank.ru" ascii //weight: 3
        $x_2_2 = "username=.*&password=.*" ascii //weight: 2
        $x_3_3 = "[MOUSE L %ux%u]" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ranbyus_G_2147645480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ranbyus.G"
        threat_id = "2147645480"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d 0c 04 75 30 81 7d fc 69 42 4b 53 75 27}  //weight: 2, accuracy: High
        $x_2_2 = {81 7d fc 93 4f 23 9a}  //weight: 2, accuracy: High
        $x_2_3 = {ff 93 00 04 00 00 ff 76 50 8d 85 ?? ?? ?? ?? ff 76 48 50 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 02 6a 0a 8d ?? 60 ?? 57 ff ?? ?? ?? ?? ?? 8a 45 63 3c 01 74 0d 3c 03 74 09}  //weight: 2, accuracy: Low
        $x_1_5 = {8b 55 0c 0f b6 14 17 c1 e1 08 0b ca 47 3b 7d 10 75 02 33 ff 4b 75 e9 31 08 83 c0 04 ff 4d 08}  //weight: 1, accuracy: High
        $x_1_6 = ".iBank*" ascii //weight: 1
        $x_1_7 = "botnet1" ascii //weight: 1
        $x_1_8 = "BSR_ANYCRLF)" ascii //weight: 1
        $x_1_9 = "%s?id=%s&session=%u&v=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ranbyus_N_2147689954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ranbyus.N"
        threat_id = "2147689954"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 0c 0f b6 14 17 c1 e1 08 0b ca 47 3b 7d 10 75 02 33 ff 4b 75 e9 31 08 83 c0 04 ff 4d 08 75}  //weight: 2, accuracy: High
        $x_1_2 = "newimaxinternetxxx.com/wav" ascii //weight: 1
        $x_1_3 = {76 26 78 45 69 52 34 33 23 24 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 79 73 74 65 6d 20 63 68 65 63 6b 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ranbyus_P_2147694631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ranbyus.P"
        threat_id = "2147694631"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranbyus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 02 d1 e8 4a 75 ee 89 04 8d 05 00 35}  //weight: 1, accuracy: Low
        $x_1_2 = "BSR_ANYCRLF)" ascii //weight: 1
        $x_1_3 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 73 73 69 6f 6e 3d [0-8] 76 3d [0-8] 6e 61 6d 65 3d [0-8] 6d 6f 64 75 6c 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

