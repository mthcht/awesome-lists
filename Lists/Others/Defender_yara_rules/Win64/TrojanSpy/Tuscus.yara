rule TrojanSpy_Win64_Tuscus_A_2147957401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Tuscus.A!AMTB"
        threat_id = "2147957401"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuscus"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SCREENSHOT" ascii //weight: 1
        $x_1_2 = "cmd /C \"tasklist.exe /SVC >> %s" wide //weight: 1
        $x_1_3 = "SYSINFO" ascii //weight: 1
        $x_1_4 = "cmd /C \"systeminfo.exe > %s" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

