rule Ransom_Win32_Stop_PA_2147741978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stop.PA!MTB"
        threat_id = "2147741978"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 03 45 ?? 33 c3 33 c6 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b de c1 e3 ?? 03 5d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {88 04 0f 89 75 ?? c1 e8 ?? 81 6d ?? ?? ?? ?? ?? 8b 45 ?? a3 ?? ?? ?? ?? 8a 45 fe 88 44 0f 01 8a 45 ff 88 44 0f 02 83 c7 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stop_A_2147767775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stop.A!MTB"
        threat_id = "2147767775"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c6 8b 75 f8 2b f8 [0-5] c1 e1 04 03 4d e4 [0-5] c1 e8 05 03 45 e8 03 f7 33 ce 33 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 45 fc 2b d9 8b 45 e0 29 45 f8 83 6d f4 01 0f 85 76 ff ff ff}  //weight: 1, accuracy: Low
        $x_10_2 = {33 c6 8b 75 f8 2b f8 [0-5] c1 e1 04 03 4d e4 [0-5] c1 e8 05 03 45 e8 03 f7 33 ce 33 c8 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 45 fc 2b d9 8b 45 e0 29 45 f8 83 6d f4 01 0f 85 76 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

