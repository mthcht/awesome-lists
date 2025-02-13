rule TrojanDropper_Win32_Autorun_AC_2147649769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Autorun.AC"
        threat_id = "2147649769"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Autorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add %cambodia% Hidden /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_2 = "copy %0 %windir%\\system32.exe /y" ascii //weight: 1
        $x_1_3 = "echo [autorun]>>%windir%\\system\\drver.cab.sys" ascii //weight: 1
        $x_1_4 = "%drive% md %%x:\\Sounds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

