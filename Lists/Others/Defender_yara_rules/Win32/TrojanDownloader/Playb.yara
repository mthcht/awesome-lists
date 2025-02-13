rule TrojanDownloader_Win32_Playb_2147628088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Playb"
        threat_id = "2147628088"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Playb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bbplay" ascii //weight: 1
        $x_1_2 = "boboplay" ascii //weight: 1
        $x_3_3 = "http://78.soupay.com/plugin/g.asp?id=" wide //weight: 3
        $x_3_4 = "Maxthon.exe,TheWorld.exe,IEXPLORE.EXE,FirefoxPortable.exe,firefox.exe,360Start.exe,360se.exe,TTraveler.exe,TT.exe,MyiQ.exe," wide //weight: 3
        $x_1_5 = "NewStartPanel\\{871C5380-42A0-1069-A2EA-08002B30309D}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

