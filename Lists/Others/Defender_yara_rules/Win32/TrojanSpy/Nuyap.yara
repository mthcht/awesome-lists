rule TrojanSpy_Win32_Nuyap_A_2147653537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nuyap.A"
        threat_id = "2147653537"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 08 33 c0 85 d2 7e 14 8b 4c 24 04 53 8a 1c 08 80 f3 ?? 88 1c 08 40 3b c2 7c f2}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 63 00 00 00 f7 f9 52 ff ?? 99 b9 63 00 00 00 f7 f9 52}  //weight: 2, accuracy: Low
        $x_1_3 = {b2 61 50 51 c6 44 24 08 75 c6 44 24 09 72}  //weight: 1, accuracy: High
        $x_1_4 = {73 64 69 6e 66 6f 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 25 64 2e 25 64 2e 25 64 2e 25 64 0d 0a 00 58 2d 46 6f 72 77 61 72 64 65 64 2d 46 6f 72 3a 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 44 53 00 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_7 = "username=%s&password=%s&templateId=&sdid=&infoEx=&uid=" ascii //weight: 1
        $x_1_8 = {4c 6f 67 69 6e 43 41 50 54 43 48 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

