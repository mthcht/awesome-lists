rule Trojan_Win32_Klackring_A_2147773229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klackring.A!dha"
        threat_id = "2147773229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klackring"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b6 b7 2d 8c c7 ?? ?? 6b 5f 14 df c7 ?? ?? b1 38 a1 73 c7 ?? ?? 89 c1 d2 c4}  //weight: 1, accuracy: Low
        $x_1_2 = {b6 b7 2d 8c c7 84 24 ?? ?? ?? ?? 6b 5f 14 df c7 84 24 ?? ?? ?? ?? b1 38 a1 73 c7 84 24 ?? ?? ?? ?? 89 c1 d2 c4}  //weight: 1, accuracy: Low
        $x_1_3 = {71 15 05 7c c7 ?? ?? 53 21 28 09 c7 ?? ?? 2c 10 35 99 c7 ?? ?? 7c 4f 58 8e}  //weight: 1, accuracy: Low
        $x_1_4 = {71 15 05 7c c7 84 24 ?? ?? ?? ?? 53 21 28 09 c7 84 24 ?? ?? ?? ?? 2c 10 35 99 c7 84 24 ?? ?? ?? ?? 7c 4f 58 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Klackring_B_2147773269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klackring.B!dha"
        threat_id = "2147773269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klackring"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 aa a2 b2 c7 ?? ?? c9 f4 f0 c6 c7 ?? ?? 62 b1 f2 e3 c7 ?? ?? 16 ae 6f 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 49 a3 8d c7 ?? ?? d8 dd 21 2b c7 ?? ?? 38 59 bb bf c7 ?? ?? 06 c0 33 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

