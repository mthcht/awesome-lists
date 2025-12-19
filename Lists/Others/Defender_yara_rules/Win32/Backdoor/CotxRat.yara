rule Backdoor_Win32_CotxRat_AR_2147959835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/CotxRat.AR!AMTB"
        threat_id = "2147959835"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "CotxRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHGetFolderPath_AppData = %s" ascii //weight: 1
        $x_1_2 = "start FakeRun pRemoteAddress == NULL" ascii //weight: 1
        $x_1_3 = "StartRunFakeExeWork" ascii //weight: 1
        $x_1_4 = "start FakeRun %s" ascii //weight: 1
        $x_1_5 = "EnterInto AntiAv_StartRunFakeExeWork" ascii //weight: 1
        $x_1_6 = "szCurrentProcessFullPath != szExePath_Real or szCurrentProcessFullPath != szExePath_Real_ProgramFiles" ascii //weight: 1
        $x_1_7 = "CreateThread: AntiDebug" ascii //weight: 1
        $x_1_8 = "AntiAv_StartRunFakeExeWork Start" ascii //weight: 1
        $x_1_9 = "decrypt passwd:%s" ascii //weight: 1
        $x_1_10 = "takeown /F \"%s\"" ascii //weight: 1
        $x_1_11 = "del \"%s\" /q /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

