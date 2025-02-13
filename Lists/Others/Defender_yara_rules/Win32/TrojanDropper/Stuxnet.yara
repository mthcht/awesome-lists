rule TrojanDropper_Win32_Stuxnet_A_2147635804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Stuxnet.A"
        threat_id = "2147635804"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Stuxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {56 8b 70 3c 03 f0 81 3e 50 45 00 00 74 04 33 c0 5e [0-8] 0f b7 46 14 53 57 8d 7c 30 18 33 c0 33 db 66 3b 46 06 73}  //weight: 3, accuracy: Low
        $x_1_2 = {74 12 0f b7 46 06 43 83 c7 28 3b d8 7c e4 33 c0}  //weight: 1, accuracy: High
        $x_3_3 = {8d 57 01 d1 ea 8d 34 0a 8a 14 06 30 14 08 40 3b 45 fc 72 f4}  //weight: 3, accuracy: High
        $x_3_4 = {81 38 0d 12 39 ae 75 ?? 8b 54 24 10 83 c0 04 89 02 8b 44 24 14}  //weight: 3, accuracy: Low
        $x_3_5 = {83 c4 0c 8d 45 80 35 dd 79 19 ae 33 c9 89 45 80}  //weight: 3, accuracy: High
        $x_1_6 = {83 bd fc fe ff ff 02 75 17 83 bd f0 fe ff ff 05 73 09 83 bd f0 fe ff ff 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

