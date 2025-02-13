rule TrojanDownloader_Win32_Baser_A_2147596939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Baser.A"
        threat_id = "2147596939"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Baser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 78 2e 35 32 32 6c 6f 76 65 2e 63 6e 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {76 76 76 2e 33 78 37 78 2e 63 6e 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\WINDOWS\\SYSTEM32\\Deledomn.bat" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\SYSTEM32\\Alletdel.bat" ascii //weight: 1
        $x_5_5 = "serverie" ascii //weight: 5
        $x_5_6 = "Drivers/klif.sys" ascii //weight: 5
        $x_5_7 = ":\\AutoRun.inf" ascii //weight: 5
        $x_5_8 = "shellexecute=" ascii //weight: 5
        $x_5_9 = "NoDriveTypeAutoRun" ascii //weight: 5
        $x_5_10 = "Auto\\command=" ascii //weight: 5
        $x_5_11 = "svchost.exe" ascii //weight: 5
        $x_5_12 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

