rule TrojanClicker_Win32_MiniGames_A_2147642140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/MiniGames.A"
        threat_id = "2147642140"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniGames"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tn=you2000" wide //weight: 2
        $x_2_2 = "tn=iewz" wide //weight: 2
        $x_2_3 = "LocationURL" wide //weight: 2
        $x_1_4 = "Navigate2" wide //weight: 1
        $x_1_5 = "&strttWinDir&" wide //weight: 1
        $x_1_6 = "nt\\3.bat" wide //weight: 1
        $x_1_7 = "\\Tencent\\smm.exe" wide //weight: 1
        $x_1_8 = "\\qqmusic.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

