rule Backdoor_Win32_Kirts_A_2147711002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kirts.A"
        threat_id = "2147711002"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kirts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f b7 4d 10 99 f7 f9 0f b6 54 15 c8 8b 45 0c 0f be 08 33 d1 8b 45 0c 88 10 8b 4d 0c 83 c1 01 89 4d 0c e9 37 ff ff ff}  //weight: 20, accuracy: High
        $x_5_2 = "shellexecute=Manager.bat" ascii //weight: 5
        $x_5_3 = "shellexecute=Manager.vbs" ascii //weight: 5
        $x_5_4 = "shellexecute=Manager.js" ascii //weight: 5
        $x_1_5 = "tasklist /FI \"IMAGENAME eq winmgr.exe" ascii //weight: 1
        $x_1_6 = "(New-Object Net.WebClient).DownloadFile('http://%s/t.exe'" ascii //weight: 1
        $x_1_7 = "CMD /C taskkill /F /IM %s" ascii //weight: 1
        $x_1_8 = "obj.run(\"DeviceManager.bat\", 0);" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

