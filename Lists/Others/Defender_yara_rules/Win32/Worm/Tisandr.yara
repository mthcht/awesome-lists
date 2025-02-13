rule Worm_Win32_Tisandr_CB_2147819049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tisandr.CB!MTB"
        threat_id = "2147819049"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tisandr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You has been infected with System" ascii //weight: 1
        $x_1_2 = "Best_pictures1992.exe" ascii //weight: 1
        $x_1_3 = "Welcome 7154NDR4" ascii //weight: 1
        $x_1_4 = "fucker_bromas.exe" ascii //weight: 1
        $x_1_5 = {68 61 63 6b 69 6e 67 20 65 6e 20 65 73 70 61 c3 b1 6f 6c 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

