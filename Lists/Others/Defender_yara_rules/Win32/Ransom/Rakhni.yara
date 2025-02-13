rule Ransom_Win32_Rakhni_S_2147742389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rakhni.S"
        threat_id = "2147742389"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rakhni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Intel\\privat.exe" wide //weight: 1
        $x_1_2 = "C:\\Intel\\bmcon.exe" wide //weight: 1
        $x_1_3 = "/v private /t reg_sz /d \"%SYSTEMDRIVE%\\Intel\\privat.exe\" /f" ascii //weight: 1
        $x_1_4 = "set pass=epsiloneridana" ascii //weight: 1
        $x_1_5 = "%SYSTEMDRIVE%\\Intel\\sender.exe -to " ascii //weight: 1
        $x_1_6 = "del /q %SYSTEMDRIVE%\\Intel\\enable.cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

