rule TrojanDownloader_Win32_Adialer_NAB_2147596688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adialer.NAB"
        threat_id = "2147596688"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://network.nocreditcard.com/DialHTML/OSB/final.php3" ascii //weight: 10
        $x_10_2 = "http://network.nocreditcard.com/DialHTML/OSB/wait.php3" ascii //weight: 10
        $x_10_3 = "RASPHONE.EXE" ascii //weight: 10
        $x_10_4 = "rnaui.dll,RnaDial" ascii //weight: 10
        $x_10_5 = "DHTMLAccess.DLL" ascii //weight: 10
        $x_1_6 = "Disconnecting..." ascii //weight: 1
        $x_1_7 = "Would you disconnect ?" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_9 = "RasGetConnectStatusA" ascii //weight: 1
        $x_1_10 = "RasEnumConnectionsA" ascii //weight: 1
        $x_1_11 = "RasHangUpA" ascii //weight: 1
        $x_1_12 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

