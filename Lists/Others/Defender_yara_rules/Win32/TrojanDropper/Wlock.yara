rule TrojanDropper_Win32_Wlock_A_2147640821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Wlock.A"
        threat_id = "2147640821"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Wlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {24 01 3c 01 74 04 d2 0b eb 02 d2 03 8a 85 ?? ?? ff ff 30 03}  //weight: 2, accuracy: Low
        $x_2_2 = {c6 41 05 ff 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff c6 42 06 e3 c7 85 ?? ?? ff ff 00 00 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "/v wlock_del /t REG_SZ /d \"cmd /c del" ascii //weight: 1
        $x_1_4 = "\\Winlogon\" /v Userinit /t REG_SZ /d \"%WINDIR%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

