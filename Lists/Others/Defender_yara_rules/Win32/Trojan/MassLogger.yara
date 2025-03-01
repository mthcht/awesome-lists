rule Trojan_Win32_Masslogger_MR_2147771423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masslogger.MR"
        threat_id = "2147771423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masslogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 c1 02 b2 60 2a d0 02 ca f6 d1 80 f1 59 80 c1 20 c0 c9 02 f6 d1 d0 c9 f6 d1 80 e9 11 32 c8 f6 d9 88 88 [0-4] 40 3d [0-4] 8a 88}  //weight: 1, accuracy: Low
        $x_1_2 = {74 27 fe c0 04 8f fe c8 2c 9e 2c 2f 2c 78 fe c8 04 85 fe c0 fe c8 fe c8 34 b9 2c 1e 04 e1 88 81 [0-4] 83 c1 01 8a 81 [0-4] 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

