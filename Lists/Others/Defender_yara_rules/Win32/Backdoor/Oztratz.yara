rule Backdoor_Win32_Oztratz_A_2147710307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oztratz.A"
        threat_id = "2147710307"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oztratz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ozone RAT.XE3" ascii //weight: 1
        $x_1_2 = {c7 45 fc ab 2a 03 00 43 81 e3 ff 00 00 00 8d 76 01 8a 94 1d ?? ?? ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d f8}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 68 ab 2a 03 00 e8 ?? ?? ?? ?? 8b d8 83 ec 08 8b d3 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 1e 81 fb 41 50 33 32 75 ?? 8b 5e 04 83 fb 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Oztratz_B_2147716336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oztratz.B"
        threat_id = "2147716336"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oztratz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 81 e3 ff 00 00 00 8d 76 01 8a 94 1d f8 fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 89 4d 08 0f b6 84 0d f8 fe ff ff 88 84 1d f8 fe ff ff 88 94 0d f8 fe ff ff 0f b6 8c 1d f8 fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d f8 fe ff ff 8b 4d fc 32 44 31 ff 8b 4d 08 88 46 ff 4f 75 a0}  //weight: 1, accuracy: High
        $x_1_2 = "Ozone RAT" ascii //weight: 1
        $x_1_3 = "data.dbf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

