rule Virus_Win32_KME_A_2147501223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/KME.A"
        threat_id = "2147501223"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "KME"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 00 20 20 20 f7 d8 3d d2 9a 87 9a c3}  //weight: 1, accuracy: High
        $x_1_2 = {ba 89 88 00 00 cd 20 96 00 01 00 c3 81 fa 89 88 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\rundll16.exe" ascii //weight: 1
        $x_1_4 = "RegisterServiceProcess" ascii //weight: 1
        $x_1_5 = "RegSetValueExA" ascii //weight: 1
        $x_1_6 = {3f 3a 5c 00 2a 2e 2a 00 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

