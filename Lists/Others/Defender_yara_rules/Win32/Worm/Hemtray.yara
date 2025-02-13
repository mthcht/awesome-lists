rule Worm_Win32_Hemtray_A_2147601553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hemtray.gen!A"
        threat_id = "2147601553"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hemtray"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 0b 33 f6 8b 4d e4 89 75 dc 51 eb 0b 8b 55 e4 c7 45 dc ff ff ff ff 52 e8 ?? ?? ?? ff ff 15 ?? ?? 40 00 9b 68 ?? ?? ?? ?? eb 24 8d 45 c4 8d 4d c8 50 51 6a 02 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = "F:\\Software komputer\\Xsignment\\Kajian Baik\\My_Heart\\My_Heart.vbp" wide //weight: 5
        $x_1_3 = "SYSTEM32\\My_Heart.exe" wide //weight: 1
        $x_1_4 = "SYSTEM32\\BrO_AcT1.exe" wide //weight: 1
        $x_1_5 = ":\\Autorun.inf" wide //weight: 1
        $x_1_6 = "[Autorun]" wide //weight: 1
        $x_1_7 = "OPEN=My_Heart.exe" wide //weight: 1
        $x_1_8 = "\\command =My_Heart.exe" wide //weight: 1
        $x_1_9 = "Shell = Auto" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

