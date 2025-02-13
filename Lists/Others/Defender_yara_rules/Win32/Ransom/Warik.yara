rule Ransom_Win32_Warik_A_2147689373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Warik.A"
        threat_id = "2147689373"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Warik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {31 f6 8d 74 26 00 8b 04 b5 ?? ?? ?? ?? 8d [0-16] e8 ?? ?? ff ff 85 c0 75 ?? 83 c6 01 81 fe ?? 00 00 00 75}  //weight: 3, accuracy: Low
        $x_3_2 = {83 c6 01 83 fe 79 0f [0-5] 8b 04 b5 ?? ?? ?? ?? 89 [0-4] 89 [0-4] e8 ?? ?? ?? ?? 85 c0 74}  //weight: 3, accuracy: Low
        $x_1_3 = "What if someone gave a war and Nobody came?" ascii //weight: 1
        $x_1_4 = "block@mail2tor.com" ascii //weight: 1
        $x_1_5 = "Nicht Kluchen! Kapitulieren!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

