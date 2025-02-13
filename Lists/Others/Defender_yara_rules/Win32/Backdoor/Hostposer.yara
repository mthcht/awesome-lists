rule Backdoor_Win32_Hostposer_A_2147655260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hostposer.A"
        threat_id = "2147655260"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostposer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 68 2c ?? 40 00 68 28 ?? 40 00 68 24 ?? 40 00 8d ?? ?? ?? e8 ?? ?? 00 00 08 00 ba ?? ?? 40 00 8d 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 e0 66 81 e3 ff 00 8b f8 89 55 84 c7 85 7c ff ff ff 08 00 00 00 79 09 66 4b 66 81 cb 00 ff 66 43 0f bf c3 8d 4d bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

