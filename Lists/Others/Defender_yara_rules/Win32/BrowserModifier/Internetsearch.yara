rule BrowserModifier_Win32_Internetsearch_125769_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Internetsearch"
        threat_id = "125769"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Internetsearch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "internetsearchservice.com" ascii //weight: 10
        $x_10_2 = "cmd.exe /C del /F /Q \"%s\\*.*\"" ascii //weight: 10
        $x_1_3 = {25 73 5c 25 73 2e 65 78 65 00 00 00 75 62 70 72 30 31}  //weight: 1, accuracy: High
        $x_1_4 = "regedit /s c:\\tmp2.reg" ascii //weight: 1
        $x_1_5 = {64 65 6c 20 22 25 73 22 00 00 3a 54 58 32 30 32}  //weight: 1, accuracy: High
        $x_1_6 = {73 65 61 72 63 68 00 00 69 65 36 2e 68 74 6d 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

