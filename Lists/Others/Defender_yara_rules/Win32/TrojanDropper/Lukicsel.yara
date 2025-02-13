rule TrojanDropper_Win32_Lukicsel_E_2147630504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lukicsel.E"
        threat_id = "2147630504"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 45 f8 50 e8 ?? ?? ?? ?? 85 c0 74 f3 8b 45 f8 8b 55 fc 0f ac d0 02 c1 ea 02 81 e0 01 00 00 00 33 d2 81 f0 01 00 00 00 81 f2 00 00 00 00 83 fa 00 75 cd 83 f8 01 75 c8 e8 ?? ff ff ff 32 06 88 07 46 47 4b 75 ba}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Lukicsel_B_2147645346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lukicsel.B"
        threat_id = "2147645346"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a c3 b9 0c 00 00 00 33 d2 f7 f1 8a 04 16 8b ?? ?? 32 02 8b ?? ?? 88 02 ff ?? ?? ff ?? ?? 8b 06 b2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

