rule TrojanSpy_MSIL_Hoetou_A_2147708559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hoetou.A"
        threat_id = "2147708559"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoetou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 76 64 65 74 65 63 74 65 64 00 61 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 63 61 6d 00 6b 79 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 6c 00 57 65 62 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 63 72 65 65 6e 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 61 72 74 4b 70 41 6e 64 44 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 75 70 70 65 72 73 69 73 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 65 6e 64 49 73 4f 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_MSIL_Hoetou_B_2147708561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hoetou.B"
        threat_id = "2147708561"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoetou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 79 6c 00 4d 6f 64 75 6c 65}  //weight: 1, accuracy: High
        $x_1_2 = {55 52 4c 46 69 6c 65 00 44 6f 77 6e 6c 6f 61 64 65 64 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {53 63 72 65 65 6e 78 00}  //weight: 1, accuracy: High
        $x_1_4 = "BytescoutScreenCapturingLib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Hoetou_C_2147708563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hoetou.C"
        threat_id = "2147708563"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoetou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BytescoutScreenCapturingLib" ascii //weight: 1
        $x_1_2 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_3 = "Host process for windows services" wide //weight: 1
        $x_1_4 = "svchost.exe" wide //weight: 1
        $x_1_5 = "6.3.9201.16421" wide //weight: 1
        $x_1_6 = "Microsoft Fonction Basic" wide //weight: 1
        $x_1_7 = "Project38.8.exe" wide //weight: 1
        $x_1_8 = "sBuild1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_MSIL_Hoetou_D_2147709687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hoetou.D!bit"
        threat_id = "2147709687"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoetou"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_2 = "Host process for windows services" wide //weight: 1
        $x_1_3 = "svchost.exe" wide //weight: 1
        $x_1_4 = "6.3.9201." wide //weight: 1
        $x_1_5 = "Microsoft Fonction Basic" wide //weight: 1
        $x_1_6 = "sBuild1.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Hoetou_E_2147711059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Hoetou.E"
        threat_id = "2147711059"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hoetou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe" wide //weight: 1
        $x_1_2 = "set_VideoRecordingTimer" ascii //weight: 1
        $x_1_3 = {00 5f 47 65 74 50 72 6f 63 65 73 73 42 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5f 53 63 72 65 65 6e 49 6d 61 67 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 43 61 70 74 75 72 65 44 69 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "get_FileManagerSocket" ascii //weight: 1
        $x_1_7 = "pluginwititle" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

