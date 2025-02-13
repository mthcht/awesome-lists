rule Trojan_Win32_Bodime_A_2147632661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bodime.A"
        threat_id = "2147632661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 44 24 ?? d5 07 66 c7 44 24 ?? 08 00 66 c7 44 24 ?? 11 00 66 c7 44 24 ?? 14 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 00 04 00 b8 4b 4b 4b 4b}  //weight: 1, accuracy: High
        $x_1_3 = "winnet.ime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bodime_C_2147633493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bodime.C"
        threat_id = "2147633493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 09 81 7d 08 03 01 00 00 75 1a 68 00 80 00 00 6a 00 56 57 e8 ?? ?? ?? ?? 0b d8 81 fe 00 f0 ff 7f 73 07 eb c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 02 80 c1 ?? 88 08 40 4e 75 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {43 41 4f 43 41 4f 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {b1 ea d7 bc ca e4 c8 eb b7 a8 c0 a9 d5 b9 b7 fe ce f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

