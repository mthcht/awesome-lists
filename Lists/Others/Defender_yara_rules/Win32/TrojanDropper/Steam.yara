rule TrojanDropper_Win32_Steam_E_2147601803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Steam.E"
        threat_id = "2147601803"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1337 SteamACC Stealer Private" wide //weight: 1
        $x_1_2 = "1337SteamLogin.txt" wide //weight: 1
        $x_1_3 = "1337SteamLogin.exe" wide //weight: 1
        $x_1_4 = "InternetConnectA" ascii //weight: 1
        $x_1_5 = "ReadServerEXE" ascii //weight: 1
        $x_1_6 = "FtpPutFileA" ascii //weight: 1
        $x_1_7 = "Steampwnt" wide //weight: 1
        $x_1_8 = "GetAndReadSteamAccountInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

