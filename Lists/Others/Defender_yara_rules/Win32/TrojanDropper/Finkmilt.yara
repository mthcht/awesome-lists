rule TrojanDropper_Win32_Finkmilt_A_2147645499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Finkmilt.A"
        threat_id = "2147645499"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 02 6a 00 6a 03 68 00 00 00 40 ff 75 08 e8 ?? ?? ?? ?? 89 45 fc 40 75 05 5b c9 c2 0c 00 ff 75 10 ff 75 0c ff 75 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 d8 fe ff ff 28 01 00 00 6a 00 6a 02 e8 ?? ?? ?? ?? 89 85 d4 fe ff ff 8d 85 d8 fe ff ff 50 ff b5 d4 fe ff ff e8 ?? ?? ?? ?? 0b c0 74 3b bf}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 8d 15 ?? ?? ?? ?? 52 6a 00 6a 01 6a 01 6a 10 8d 15 ?? ?? ?? ?? 52 52 56 ff d0 85 c0}  //weight: 1, accuracy: Low
        $x_1_4 = "\\dfrti.sys" ascii //weight: 1
        $x_1_5 = "\\drivers\\etc\\host5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Finkmilt_B_2147650676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Finkmilt.B"
        threat_id = "2147650676"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0d 8b f8 57 e8 ?? ?? ?? ?? 89 45 14 eb 02 eb 06 46 83 fe 64 76 d6}  //weight: 1, accuracy: Low
        $x_1_2 = {fc 33 c0 b9 ff ff ff ff f2 ae 38 07 75 de}  //weight: 1, accuracy: High
        $x_1_3 = {ff 4d 08 ff 75 08 e8 c1 ff ff ff c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\drivers\\etc\\host5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Finkmilt_C_2147650980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Finkmilt.C"
        threat_id = "2147650980"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Finkmilt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc 33 c0 6a ff 59 f2 ae 38 07 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {ff 4d 08 ff 75 08 e8 c1 ff ff ff c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 09 01 01 01 01 01 01 01 01 01 31 32 33 34 35 36 37 38 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

