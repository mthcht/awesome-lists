rule TrojanSpy_Win32_CoinSteal_G_2147730114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/CoinSteal.G!bit"
        threat_id = "2147730114"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 32 44 19 ff ff 8d e8 fd ff ff 88 43 ff 75 06 00 8b ?? ?? fd ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "SetClipboardData" ascii //weight: 1
        $x_1_3 = "EmptyClipboard" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

