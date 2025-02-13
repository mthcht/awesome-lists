rule TrojanDropper_MSIL_Zilla_MA_2147917203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zilla.MA!MTB"
        threat_id = "2147917203"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 02 6f 12 00 00 0a 0c de 0a}  //weight: 1, accuracy: High
        $x_1_2 = "stage2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Zilla_SA_2147920861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zilla.SA!MTB"
        threat_id = "2147920861"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "get_crab" ascii //weight: 1
        $x_1_2 = "Don't open this file for your safety" ascii //weight: 1
        $x_1_3 = "Reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_4 = "net user %username% /fullname:\"MR KRABS WAS HERE!\"" ascii //weight: 1
        $x_1_5 = {63 6f 70 79 20 2f 79 20 22 25 74 65 6d 70 25 [0-15] 2e 65 78 65 22 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Zilla_NIT_2147925282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zilla.NIT!MTB"
        threat_id = "2147925282"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 3c 00 00 0a 6f 3d 00 00 0a 6f 3e 00 00 0a 06 18 6f 3f 00 00 0a 06 6f 40 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 41 00 00 0a 0b}  //weight: 2, accuracy: High
        $x_1_2 = "cxrsldg" wide //weight: 1
        $x_1_3 = "%AppData%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

