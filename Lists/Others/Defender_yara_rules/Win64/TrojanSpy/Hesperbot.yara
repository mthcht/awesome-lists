rule TrojanSpy_Win64_Hesperbot_A_2147683037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Hesperbot.A"
        threat_id = "2147683037"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 8d 05 58 bd 00 00 48 8b d3 b9 0a 00 00 00 4c 2b c3 0f 1f 44 00 00 41 0f b6 04 10 48 ff c2 48 ff c9 88 42 ff 75}  //weight: 5, accuracy: High
        $x_5_2 = "keylog_mod_x64.mod" ascii //weight: 5
        $x_5_3 = "[del]" wide //weight: 5
        $x_3_4 = "InstallDate" ascii //weight: 3
        $x_3_5 = "DigitalProductId" ascii //weight: 3
        $x_3_6 = "MachineGuid" ascii //weight: 3
        $x_1_7 = "\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_8 = "\\Microsoft\\Cryptography" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_Hesperbot_K_2147690324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Hesperbot.K"
        threat_id = "2147690324"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 f7 b6 98 63 bb a6 ba 79 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 0c 48 8b c1}  //weight: 1, accuracy: High
        $x_1_2 = {b8 ab aa aa 2a f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 03 c0 2b c8 48 63 c1}  //weight: 1, accuracy: High
        $x_1_3 = {b8 56 55 55 55 f7 2f 8b c2 c1 e8 1f 03 d0 03 d2 3b f2 7e 07}  //weight: 1, accuracy: High
        $x_1_4 = {b8 37 97 3a 66 48 83 fa ff 75 13 41 8b d1 66 44 39 09 74 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

