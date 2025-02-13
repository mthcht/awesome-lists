rule PUA_Win32_SystemHealer_224906_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/SystemHealer"
        threat_id = "224906"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemHealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/inst?sid=%SID%&hid=%HID%&os=%" wide //weight: 1
        $x_1_2 = " Monitor\" /F /RL HIGHEST" wide //weight: 1
        $x_1_3 = ".exe\\\" -scan\" /sc ONCE /st " wide //weight: 1
        $x_1_4 = " Run Delay\" /F /RL HIGHEST" wide //weight: 1
        $x_10_5 = "\\wininit.ini" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

