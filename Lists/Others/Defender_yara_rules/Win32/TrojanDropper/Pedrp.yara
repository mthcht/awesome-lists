rule TrojanDropper_Win32_Pedrp_A_2147657117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pedrp.A"
        threat_id = "2147657117"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pedrp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 14 3e 32 d0 88 14 3e 46 3b f3 72 e0}  //weight: 1, accuracy: High
        $x_1_2 = {83 c9 ff 33 c0 c6 44 24 ?? 76 c6 44 24 ?? 6f c6 44 24 ?? 2e c6 44 24 ?? 68 88 54 24 10}  //weight: 1, accuracy: Low
        $x_1_3 = {f3 a5 8b cb 68 80 00 00 00 83 e1 03 f3 a4 8b 3d ?? ?? ?? ?? 6a 03 50 6a 01 8d 44 24 ?? 68 00 00 00 80 50 ff d7}  //weight: 1, accuracy: Low
        $x_1_4 = "\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

