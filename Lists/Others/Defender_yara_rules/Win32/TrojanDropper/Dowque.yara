rule TrojanDropper_Win32_Dowque_A_2147582056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dowque.A"
        threat_id = "2147582056"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowque"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 ff 00 00 00 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ff 85 c0 75 07 c6 85 00 ff ff ff 43}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 85 00 ff ff ff 50 e8 ?? ?? ?? ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43}  //weight: 2, accuracy: Low
        $x_1_3 = "Explorer\\PLUGINS\\" ascii //weight: 1
        $x_1_4 = "HookOn" ascii //weight: 1
        $x_2_5 = "if exist \"" ascii //weight: 2
        $x_1_6 = "Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_7 = "SystemKb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

