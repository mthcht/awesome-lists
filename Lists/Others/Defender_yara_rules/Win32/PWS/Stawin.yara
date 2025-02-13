rule PWS_Win32_Stawin_C_2147641310_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stawin.C"
        threat_id = "2147641310"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stawin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {80 f9 0d 74 0f 80 f9 1b 74 0a 80 f9 08 74 05 80 f9 09 75}  //weight: 4, accuracy: High
        $x_2_2 = "GetKeyboardState" ascii //weight: 2
        $x_2_3 = "Hooker.dll" ascii //weight: 2
        $x_2_4 = "Citibank" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

