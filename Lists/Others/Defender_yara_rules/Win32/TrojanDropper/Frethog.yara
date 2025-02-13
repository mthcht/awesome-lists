rule TrojanDropper_Win32_Frethog_N_2147596324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Frethog.N"
        threat_id = "2147596324"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upxdnd.exe" ascii //weight: 1
        $x_1_2 = "upxdnd.dll" ascii //weight: 1
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = "51343281" ascii //weight: 1
        $x_1_5 = {50 ff 15 24 20 40 00 8d 85 e0 fc ff ff 56 50 8d 85 e4 fd ff ff 50 ff d7 8d 85 e0 fc ff ff 68 cc 30 40 00 50 e8 52 08 00 00 8d 85 e0 fc ff ff 68 94 30 40 00 50 e8 41 08 00 00 83 c4 10 8d 85 e0 fc ff ff 53 50 8d 85 dc fb ff ff 50 ff 15 84 20 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Frethog_E_2147606982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Frethog.E"
        threat_id = "2147606982"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 08 50 68 73 00 09 00 ff 76 2c ff 15 ?? ?? ?? 00 85 c0 74 09 6a 01 89 9e 98 61 00 00 58}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 37 fc 4b 43 55 46 89 30 8b c7 5f}  //weight: 1, accuracy: High
        $x_1_3 = {83 7d fc 64 73 ?? 6a 02 53 6a fc 58 2b 45 fc 50 ff 75 f4 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Frethog_AW_2147630936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Frethog.AW"
        threat_id = "2147630936"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhengtu.dat" ascii //weight: 1
        $x_1_2 = "%s\\DLLCache\\llk%d.dll" ascii //weight: 1
        $x_1_3 = "\\DLLCache\\ksuser.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

