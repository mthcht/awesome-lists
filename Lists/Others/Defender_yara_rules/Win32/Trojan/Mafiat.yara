rule Trojan_Win32_Mafiat_2147655879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mafiat"
        threat_id = "2147655879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafiat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 89 c3 89 d6 8b 79 fc 8b 56 fc 01 fa f7 c2 00 00 00 c0 75 52 39 ce 74 41 e8 ?? ?? ?? ?? 89 f0 8b 4e fc 6a 00 66 83 7e f6 02 74 0f 89 c2 89 e0 e8 ?? ?? ?? ?? 8b 04 24 8b 48 fc 8b 13 d1 e7 01 fa d1 e1 e8 ?? ?? ?? ?? 89 e0 8b 10 85 d2 74 05 e8 ?? ?? ?? ?? 58}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 80 7b 28 00 75 08 8b 43 20 89 04 24 eb 2f 8b cc 8b d6 8b c3 8b 28 ff 95 ?? ?? ?? ?? 84 c0 74 1d 0f b6 43 29 2c 01 72 26 fe c8 74 02 eb 0f 8b 15 64 bb 41 00 33 c9 8b c3}  //weight: 1, accuracy: Low
        $x_1_3 = "kkill -f -im fi" wide //weight: 1
        $x_1_4 = "del *.b" wide //weight: 1
        $x_1_5 = "t (goto l" wide //weight: 1
        $x_1_6 = "d Mozill" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

