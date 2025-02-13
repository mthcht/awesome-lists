rule Virus_Win32_Yupfil_A_2147648463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Yupfil.A"
        threat_id = "2147648463"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Yupfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ijlGetLibVersion" ascii //weight: 1
        $x_1_2 = "ijlInit" ascii //weight: 1
        $x_1_3 = "ijlFree" ascii //weight: 1
        $x_1_4 = "ijlRead" ascii //weight: 1
        $x_1_5 = "ijlWrite" ascii //weight: 1
        $x_1_6 = "ijlErrorStr" ascii //weight: 1
        $x_1_7 = {6d 66 63 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

