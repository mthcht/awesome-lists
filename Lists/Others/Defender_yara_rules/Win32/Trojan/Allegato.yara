rule Trojan_Win32_Allegato_MA_2147841631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Allegato.MA!MTB"
        threat_id = "2147841631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Allegato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 08 6e cf ee 88 da ae 07 13 12 94 ee 94 ad de 71 72 c2 2d 85 c2 9a 53 0f 91 c7 70 6d ad 67 e7 2e bf 10 89 46 79 15 6f 93 39 3f 67}  //weight: 5, accuracy: High
        $x_5_2 = {df 7a bc 3f 22 d7 52 ec 10 d7 d2 45 6e de 4a 89 74 d5 6b 1e d4 11 db ac 60 ce 63 61 ff 92 16 84 11 2d 92 dd ec a1 13 f8 05 6a 17}  //weight: 5, accuracy: High
        $x_5_3 = {06 00 34 00 35 00 36 00 39 00 37 00 44 00 06 00 43 00 33 00 43 00 30 00 41 00 45 00 06}  //weight: 5, accuracy: High
        $x_3_4 = "host.exe" wide //weight: 3
        $x_1_5 = "TShiftState" ascii //weight: 1
        $x_1_6 = "TKeyPressEvent" ascii //weight: 1
        $x_1_7 = "MousePos" ascii //weight: 1
        $x_1_8 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Allegato_MA_2147841631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Allegato.MA!MTB"
        threat_id = "2147841631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Allegato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {da d5 d5 9a dd 51 18 dc 4c d9 9d b4 df 1e 83 75 3b a7 ea 24 54 00 ff 68 59 04 0b 0d cc ca ba 24 99 80 9d a8 e7 50 95 87 23 02 c9 c5 b8 ca 38 d2}  //weight: 5, accuracy: High
        $x_5_2 = {0b 8a d8 7d 71 a9 ee 48 c2 26 36 cf c9 7b 79 19 75 7d 0c b1 d9 2b 16 c8 ee 84 ee 4c 58 ed 67 93 75 cf 96 8b a0 5e f1 d6 af c6 26 47 ae ff 94 bb}  //weight: 5, accuracy: High
        $x_5_3 = {23 f0 1b da 4d 8c 3c 8a d6 ee ec d3 c4 e9 2c 9a 71 6c 71 95 b2 37 a0 71 b7 a7 6a 52 ce 3f 57 d8 0b 77 c8 47 91 d5 9b e5 c3 14 97 46 7c 44 d5 ee 56 b1 b5 07 1d fb b5 8c e4 71 dc ba 60 b6 a2 d0}  //weight: 5, accuracy: High
        $x_3_4 = {e0 00 8e 81 0b 01 02 19 00 e8 05 00 00 7c 0e 00 00 00 00 00 38 95 05 00 00 10 00 00 00 00 06 00 00 00 40}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

