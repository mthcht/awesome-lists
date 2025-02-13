rule TrojanDownloader_Win32_Dembr_A_2147680008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dembr.A"
        threat_id = "2147680008"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dembr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8d 70 01 8d 9b 00 00 00 00 8a 10 40 84 d2 75 f9 2b c6 3b c8 72 d7 5f a1}  //weight: 10, accuracy: High
        $x_1_2 = "TGIITGM1GSER:<491MRPX:6=45415GQ4446456" ascii //weight: 1
        $x_1_3 = "WSJX[EVI``Qmgvswsjx``[mrhs{w$RX``GyvvirxZivwmsr" ascii //weight: 1
        $x_1_4 = "``xmr}mrm5" ascii //weight: 1
        $x_1_5 = "Mrxivzep$)h$mw$wix$Wyggiww% hs{r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dembr_B_2147680011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dembr.B"
        threat_id = "2147680011"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dembr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {75 f9 2b c2 3d b8 0b 00 00 77 44 8b c3 56 33 c9 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 74 30}  //weight: 10, accuracy: High
        $x_1_2 = "TGIITGM1GSER:<491MRPX:6=45415GQPMQ6456" ascii //weight: 1
        $x_1_3 = "W]WXIQ`GyvvirxGsrxvspWix`wivzmgiw`Wglihypi" ascii //weight: 1
        $x_1_4 = "Hitirirg}" ascii //weight: 1
        $x_1_5 = {57 69 76 7a 6d 67 69 51 65 6d 72 00 6d 72 6d 32 68 70 70 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

