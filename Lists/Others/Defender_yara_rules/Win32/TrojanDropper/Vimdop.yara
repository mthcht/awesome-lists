rule TrojanDropper_Win32_Vimdop_A_2147708917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vimdop.A!bit"
        threat_id = "2147708917"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimdop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\usb.vbp" wide //weight: 1
        $x_1_2 = "/bot.php" wide //weight: 1
        $x_1_3 = "REG ADD HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "/v microsoftflash /t REG_EXPAND_SZ /d %SystemRoot%\\system32" wide //weight: 1
        $x_1_5 = "/v Hidden /t REG_DWORD /d 00000002 /f" wide //weight: 1
        $x_1_6 = "/v SuperHidden /t REG_DWORD /d 00000000 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

