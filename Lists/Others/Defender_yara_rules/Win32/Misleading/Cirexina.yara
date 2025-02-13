rule Misleading_Win32_Cirexina_240828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Cirexina"
        threat_id = "240828"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Cirexina"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PC Fix Cleaner" wide //weight: 1
        $x_1_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 43 00 46 00 69 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "http://www.pc-fix-cleaner.com/" wide //weight: 1
        $x_1_4 = "Global\\MutexWinTurbo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Win32_Cirexina_240828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Cirexina"
        threat_id = "240828"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Cirexina"
        severity = "18"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\PCFixBooster" wide //weight: 1
        $x_1_2 = "PC Fix Booster" wide //weight: 1
        $x_1_3 = "http://www.pc-fix-booster.com/" wide //weight: 1
        $x_1_4 = "Global\\MutexWinTurbo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

