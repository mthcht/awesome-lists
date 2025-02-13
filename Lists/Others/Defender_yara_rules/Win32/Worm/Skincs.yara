rule Worm_Win32_Skincs_A_2147582089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Skincs.A"
        threat_id = "2147582089"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Skincs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "explorer\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_2 = "C$\\Setup.exe" ascii //weight: 1
        $x_1_3 = "C$\\AutoExec.bat" ascii //weight: 1
        $x_1_4 = "if exist " ascii //weight: 1
        $x_1_5 = "goto try" ascii //weight: 1
        $x_1_6 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_7 = "[AutoRun]" ascii //weight: 1
        $x_1_8 = "Policies\\Explorer" ascii //weight: 1
        $x_1_9 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_10 = "OpenSCManagerA" ascii //weight: 1
        $x_1_11 = ":\\AutoRun.inf" ascii //weight: 1
        $x_1_12 = "livekiss.cn/ma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

