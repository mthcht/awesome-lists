rule TrojanSpy_Win32_Embed_A_2147646260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Embed.A"
        threat_id = "2147646260"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Embed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ffnos|&tm**,L0FG" ascii //weight: 4
        $x_1_2 = "Mcafee FrameWork :(" wide //weight: 1
        $x_1_3 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 6c 61 79 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 73 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Embed_A_2147646260_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Embed.A"
        threat_id = "2147646260"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Embed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f3 a5 8d 48 02 b8 ab aa aa aa f7 e1 d1 ea a4 8d 04 52 89 45 f0}  //weight: 2, accuracy: High
        $x_2_2 = {6a 04 50 56 c7 44 24 30 d4 c3 b2 a1 ff d7}  //weight: 2, accuracy: High
        $x_2_3 = {68 88 13 00 00 ff d6 8d 4c 24 08 6a 00 51 ff d7 85 c0 74 ec 68 10 27 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 6c 61 79 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {57 69 6e 73 33 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Embed_B_2147658652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Embed.B"
        threat_id = "2147658652"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Embed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 89 45 f8 03 c0 83 c0 03 24 fc e8 ?? ?? ?? ?? 8b c4 ff 75 f8 89 45 f0 50 6a ff ff 75 fc 66 89 18}  //weight: 1, accuracy: Low
        $x_1_2 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 46 00 72 00 61 00 6d 00 65 00 57 00 6f 00 72 00 6b 00 20 00 21 00 7e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "/windows/update/search?hl=%s&q=%s&meta=%s&id=%s" ascii //weight: 1
        $x_1_5 = "netstat -ano >>" ascii //weight: 1
        $x_1_6 = {57 68 61 74 54 68 65 46 75 63 6b 69 6e 67 49 73 47 6f 69 6e 67 4f 6e 48 69 4d 61 6e 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

