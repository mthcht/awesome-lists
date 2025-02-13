rule Backdoor_Win32_Firefly_J_2147604829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Firefly.J"
        threat_id = "2147604829"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Firefly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FireFly" ascii //weight: 1
        $x_1_2 = "Serpent.dll" ascii //weight: 1
        $x_1_3 = "hzxhzx123" ascii //weight: 1
        $x_10_4 = {64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45}  //weight: 10, accuracy: Low
        $x_10_5 = {6a 01 8d 44 24 10 50 e8 ?? ?? ?? ?? 6a 00 6a 00 6a ff 8d 44 24 18 50 e8 ?? ?? ?? ?? c7 04 24 0c 00 00 00 8d 44 24 0c 89 44 24 04 c7 44 24 08 ff ff ff ff 68 ?? ?? ?? ?? 6a ff 6a 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

