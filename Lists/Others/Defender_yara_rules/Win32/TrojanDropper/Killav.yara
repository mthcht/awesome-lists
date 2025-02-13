rule TrojanDropper_Win32_Killav_A_2147684237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Killav.A"
        threat_id = "2147684237"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 69 74 6c 65 20 59 6f 75 20 44 45 41 44 21 21 21 21 21 21 21 [0-8] 73 65 74 20 74 61 73 6b 6b 69 6c 6c 3d 73}  //weight: 10, accuracy: Low
        $x_1_2 = "%s% /im ESAFE /f >nul" ascii //weight: 1
        $x_1_3 = "%s% /im KAV* /f >nul" ascii //weight: 1
        $x_1_4 = "%s% /im norton* /f >nul" ascii //weight: 1
        $x_1_5 = "%s% /im ZONEALARM /f >nul" ascii //weight: 1
        $x_10_6 = "for %%c in (c %alldrive%) do del %%c:\\*.gho /f /s /q >nul" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

