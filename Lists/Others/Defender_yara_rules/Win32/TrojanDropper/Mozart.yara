rule TrojanDropper_Win32_Mozart_AR_2147750655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mozart.AR!MSR"
        threat_id = "2147750655"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mozart"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "93.188.155.2" wide //weight: 1
        $x_1_2 = "mozart.txt" wide //weight: 1
        $x_1_3 = "move \"%TEMP%\\" wide //weight: 1
        $x_1_4 = "\" \"%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

