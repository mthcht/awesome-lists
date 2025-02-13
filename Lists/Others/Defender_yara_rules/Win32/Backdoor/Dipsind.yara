rule Backdoor_Win32_Dipsind_C_2147707040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dipsind.C!dha"
        threat_id = "2147707040"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dipsind"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 e8 07 d0 e1 0a c1 8a c8 32 d0 c0 e9 07 d0 e0 0a c8 32 ca 80 f1 63}  //weight: 1, accuracy: High
        $x_1_2 = {68 a1 86 01 00 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa}  //weight: 1, accuracy: High
        $x_1_3 = {b8 ab aa aa aa 8b b4 24 ?? 00 00 00 8b 8c 24 ?? 00 00 00 8d 57 02 83 c4 ?? f7 e2 8b 84 24 f8 00 00 00 8b da d1 eb c1 e3 02 85 c0 74 02 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

