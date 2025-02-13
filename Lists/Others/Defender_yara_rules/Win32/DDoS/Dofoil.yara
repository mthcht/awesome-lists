rule DDoS_Win32_Dofoil_A_2147651353_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Dofoil.A"
        threat_id = "2147651353"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 06 ac 32 c2 aa e2 fa 61 8b 45 f4 8b e5 5d c3}  //weight: 2, accuracy: High
        $x_2_2 = {81 c7 04 05 00 00 b8 56 71 64 4f ab b8 23 65 65 6c ab}  //weight: 2, accuracy: High
        $x_2_3 = {8b 75 08 6a 06 56 a1 ?? ?? ?? ?? 8b (40 ??|80 ?? ?? ?? ??) ff d0 68 00 04 00 00 e8 ?? ?? ?? ?? 8b d8 68 00 04 00 00 53}  //weight: 2, accuracy: Low
        $x_1_4 = {c7 45 f8 68 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

