rule TrojanSpy_Win32_ThripKeyLogger_2147727787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/ThripKeyLogger"
        threat_id = "2147727787"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "ThripKeyLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\help\\CNDY.DAT" ascii //weight: 2
        $x_1_2 = "Unknown Virtual-Key Code" ascii //weight: 1
        $x_1_3 = "LoadLibraryA() failed in KbdGetProcAddressByName()" ascii //weight: 1
        $x_1_4 = "CreateWindow() failed in KbdRegisterCreateHideWindow()" ascii //weight: 1
        $x_1_5 = "RegisterRawInputDevices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

