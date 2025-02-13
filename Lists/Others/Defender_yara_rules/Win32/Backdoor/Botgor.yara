rule Backdoor_Win32_Botgor_A_2147611532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Botgor.A"
        threat_id = "2147611532"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Botgor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bots_controller.php" ascii //weight: 5
        $x_5_2 = "guid_bot=" ascii //weight: 5
        $x_5_3 = "Virus is started!" ascii //weight: 5
        $x_5_4 = "EXE is successfully infected" ascii //weight: 5
        $x_1_5 = "viagra" ascii //weight: 1
        $x_1_6 = "marihuana" ascii //weight: 1
        $x_1_7 = "erotic" ascii //weight: 1
        $x_1_8 = "*penis*" ascii //weight: 1
        $x_1_9 = "*sex*" ascii //weight: 1
        $x_1_10 = "*porno*" ascii //weight: 1
        $x_1_11 = "*purchase*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 6 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Botgor_B_2147611533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Botgor.B"
        threat_id = "2147611533"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Botgor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "86"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Cannot execute program! Application will be terminated" ascii //weight: 20
        $x_20_2 = "datafile1" ascii //weight: 20
        $x_20_3 = {00 20 2d 63 75 72 65 00}  //weight: 20, accuracy: High
        $x_20_4 = {00 62 6f 74 31 2e 65 78 65}  //weight: 20, accuracy: High
        $x_1_5 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "IsBadReadPtr()" ascii //weight: 1
        $x_1_7 = "!CreateProcess()" ascii //weight: 1
        $x_3_8 = "C:\\MyRep.dat" ascii //weight: 3
        $x_3_9 = "\"MAIN_EXE\"" ascii //weight: 3
        $x_3_10 = {c7 45 f4 b9 79 37 9e c7 45 ec 20 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_20_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((4 of ($x_20_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

