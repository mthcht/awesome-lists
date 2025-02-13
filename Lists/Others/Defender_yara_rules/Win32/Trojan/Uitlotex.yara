rule Trojan_Win32_Uitlotex_A_2147634551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uitlotex.A"
        threat_id = "2147634551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uitlotex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 53 8d 63 6e 9c a7 1a c6 dd 39 4e 35 8d ba 72 9c 6b 1b 74 e5 38 d6}  //weight: 1, accuracy: High
        $x_1_2 = {a7 29 c6 b1 b7 4e 53 8d 63 6e 9c a7 1a c6 dd 39 4e 35 8d ba 72 9c 6b}  //weight: 1, accuracy: High
        $x_1_3 = {e5 4e 58 d7 df 8e df 5b f9 53 96 35 f7 e3 b7 d6 fe 54 e5 8d 7d f8 ed}  //weight: 1, accuracy: High
        $x_1_4 = {5b ea 32 fe 0e 7c 72 d7 d7 74 fb bc 6a ff 00 24 8f c9 cb f0 61 f0 9a}  //weight: 1, accuracy: High
        $x_1_5 = {7e 33 bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 46 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 8b c7 8b 55 f8 e8 ?? ?? ?? ?? 43 4e 75 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

