rule Trojan_Win32_Sucoruq_A_2147697017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sucoruq.A"
        threat_id = "2147697017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sucoruq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "1bpsgko,yp1nqaesfa/lgsv+17trwd " wide //weight: 4
        $x_2_2 = {68 80 a9 03 00 e8 ?? ?? ?? ff 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20}  //weight: 2, accuracy: Low
        $x_2_3 = {7c 00 75 00 7c 00 64 00 76 00 62 00 66 00 63 00 38 00 6c 00 6c 00 35 00 6c 00 66 00 3d 00 62 00 76 00 67 00 64 00 64 00 6e 00 66 00 69 00 63 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "[x] GetPost" wide //weight: 1
        $x_1_5 = {75 0c c7 83 bc 01 00 00 46 27 00 00 eb 0d 8b 55 fc 8b c3 8b 08 ff 91 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

