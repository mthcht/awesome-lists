rule TrojanSpy_Win32_Hesperbot_B_2147686352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hesperbot.B"
        threat_id = "2147686352"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_2 = "%_HESP_BOT_ID_%" ascii //weight: 1
        $x_1_3 = "$_HESP_REQ_TYPE_$" ascii //weight: 1
        $x_1_4 = "S:(ML;;NRNWNX;;;LW)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Hesperbot_L_2147691028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hesperbot.L"
        threat_id = "2147691028"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 d4 23 2a 89 45 e0 89 5d e4 89 7d e8 89 7d ec c7 45 f0 05 00 00 00 e8}  //weight: 1, accuracy: High
        $x_2_2 = {b8 db 4b 68 2f f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 36 8b d6 2b d0 8b 03 8a 92}  //weight: 2, accuracy: High
        $x_1_3 = {b1 19 0f e8 4c ff 58 51 51 ad 54 f7 ce fd bc 97 83 79 fa 32 cb ea 54 2d fd c3 2d 69 7e 45 0d 9d}  //weight: 1, accuracy: High
        $x_1_4 = {c2 b7 71 00 e2 56 49 bc 1b be 0a 14 0d e0 3d 94 bc 92 cf f8 e5 0d a6 65 a2 84 30 42 8a b0 0d 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

