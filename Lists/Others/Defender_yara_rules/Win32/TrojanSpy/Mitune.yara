rule TrojanSpy_Win32_Mitune_A_2147597205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Mitune.A"
        threat_id = "2147597205"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Mitune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apple.com/itunes/" ascii //weight: 1
        $x_1_2 = "Can't found the iTunes on your system" ascii //weight: 1
        $x_1_3 = "Are you want to download a iTunes now" ascii //weight: 1
        $x_1_4 = "musicmatch.com" ascii //weight: 1
        $x_1_5 = "Can't found the MusicMatch Jukebox on your system" ascii //weight: 1
        $x_1_6 = "Are you want to download a MUSICMATCH Jukebox now" ascii //weight: 1
        $x_1_7 = "sndrec32.exe" ascii //weight: 1
        $x_1_8 = "sndvol32.exe" ascii //weight: 1
        $x_1_9 = "cdplayer.exe" ascii //weight: 1
        $x_1_10 = "wmplayer.exe" ascii //weight: 1
        $x_1_11 = "FRONTPG.EXE" ascii //weight: 1
        $x_1_12 = "POWERPNT.EXE" ascii //weight: 1
        $x_1_13 = "EXCEL.EXE" ascii //weight: 1
        $x_1_14 = "WINWORD.EXE" ascii //weight: 1
        $x_1_15 = "mspaint.exe" ascii //weight: 1
        $x_1_16 = "notepad.exe" ascii //weight: 1
        $x_1_17 = "calc.exe" ascii //weight: 1
        $x_1_18 = "msimn.exe" ascii //weight: 1
        $x_1_19 = "OpenClipboard" ascii //weight: 1
        $x_1_20 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

