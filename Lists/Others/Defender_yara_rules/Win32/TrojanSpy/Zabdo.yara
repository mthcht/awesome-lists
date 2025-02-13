rule TrojanSpy_Win32_Zabdo_A_2147601582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Zabdo.A"
        threat_id = "2147601582"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zabdo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "F:\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_5_2 = "HideProcess" ascii //weight: 5
        $x_5_3 = "RASEntriesNT" ascii //weight: 5
        $x_5_4 = "*sup*DanlodBazar*" wide //weight: 5
        $x_5_5 = "YOU HAVE A REMOTE SHELL TO " wide //weight: 5
        $x_5_6 = "\"TrueVector Internet Monitor\"" wide //weight: 5
        $x_5_7 = "DBSpy: Data from IP " wide //weight: 5
        $x_5_8 = "ftp -s:C:\\txt.txt" wide //weight: 5
        $x_5_9 = "The victim's Dialup Information is:" wide //weight: 5
        $x_1_10 = "taskkill /f /im spyhunter.exe" wide //weight: 1
        $x_1_11 = "taskkill /f /im spyswaper.exe" wide //weight: 1
        $x_1_12 = "taskkill /f /im GIANTAntiSpyWareMain.exe" wide //weight: 1
        $x_1_13 = "taskkill /f /im norton.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_5_*))) or
            (all of ($x*))
        )
}

