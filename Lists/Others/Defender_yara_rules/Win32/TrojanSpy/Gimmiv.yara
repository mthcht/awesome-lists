rule TrojanSpy_Win32_Gimmiv_A_2147800944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gimmiv.A"
        threat_id = "2147800944"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gimmiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WScript.CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 10
        $x_10_2 = "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 10
        $x_10_3 = "reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 10
        $x_10_4 = "net stop %s" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_6 = {2e 76 62 73 [0-16] 6e 6f 74 65 70 61 64 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_2_7 = "SOFTWARE\\BitDefender" ascii //weight: 2
        $x_2_8 = "SOFTWARE\\Jiangmin" ascii //weight: 2
        $x_2_9 = "SOFTWARE\\KasperskyLab" ascii //weight: 2
        $x_2_10 = "SOFTWARE\\Kingsoft" ascii //weight: 2
        $x_2_11 = "SOFTWARE\\Symantec\\PatchInst\\NIS" ascii //weight: 2
        $x_2_12 = "SOFTWARE\\Microsoft\\OneCare Protection" ascii //weight: 2
        $x_2_13 = "SOFTWARE\\rising" ascii //weight: 2
        $x_2_14 = "SOFTWARE\\TrendMicro" ascii //weight: 2
        $x_1_15 = "DecryptFileAES" ascii //weight: 1
        $x_1_16 = ".DeleteFile \"%s" ascii //weight: 1
        $x_1_17 = "nxrestart.bat" ascii //weight: 1
        $x_1_18 = "nbzclean.bat" ascii //weight: 1
        $x_1_19 = "ctfmon.exe" ascii //weight: 1
        $x_1_20 = "WScript.Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

