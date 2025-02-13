rule VirTool_Win32_Dijecto_B_2147695869_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dijecto.B"
        threat_id = "2147695869"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dijecto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 68 69 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 72 72 6f 72 20 69 6e 20 61 6c 6f 63 61 74 69 6e 67 20 6d 6d 65 6f 72 79 21 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = "DigitRec..." wide //weight: 1
        $x_1_4 = {8b 4c 24 60 8b 44 24 74 dd 84 24 9c 00 00 00 8b 09 83 c4 50 83 c0 08 ba 04 00 00 00 dd 00 dc 21 83 c0 08 83 c1 08 4a d9 c0 d8 c9 de c2 dd d8 75 eb}  //weight: 1, accuracy: High
        $x_1_5 = {dc 5d 18 df e0 f6 c4 01 75 14 8b 44 24 1c 40 3d 98 3a 00 00 89 44 24 1c 0f 8c 4e fe ff ff 8b 4d 10 8b 54 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

