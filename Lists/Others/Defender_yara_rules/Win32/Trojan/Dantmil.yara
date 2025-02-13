rule Trojan_Win32_Dantmil_A_2147646568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dantmil.A"
        threat_id = "2147646568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dantmil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 b5 28 ff ff ff 89 b5 20 ff ff ff 8d 45 ?? 89 85 d4 fe ff ff c7 85 cc fe ff ff 08 40 00 00 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b f0 8d 4d b0 51 8d 55 a0 52 8d 45 90 50 ff d7 50 8d 8d 70 ff ff ff 51 8d 95 60 ff ff ff 52}  //weight: 2, accuracy: High
        $x_2_3 = {66 83 39 01 75 15 8b 71 14 8b 41 10 f7 de 3b f0 72 05 ff d7 8b 4d e4}  //weight: 2, accuracy: High
        $x_1_4 = "D0564EF474CF921D3A462FB8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dantmil_C_2147647886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dantmil.C"
        threat_id = "2147647886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dantmil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8d 45 d4 50 8d 45 d8 50 6a 02 e8 ?? ?? ?? ?? 83 c4 0c c7 45 fc 06 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8d 4d bc e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d0 8d 4d b8}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 fc fe ff ff 50 6a 10 68 80 08 00 00 e8 ?? ?? ?? ?? 83 c4 1c c7 85 f4 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

