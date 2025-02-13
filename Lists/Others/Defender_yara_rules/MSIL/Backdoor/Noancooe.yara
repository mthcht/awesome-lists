rule Backdoor_MSIL_Noancooe_A_2147686450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.A"
        threat_id = "2147686450"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NanoCore Clien" ascii //weight: 1
        $x_1_2 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_A_2147686450_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.A"
        threat_id = "2147686450"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NanoCore.exe" ascii //weight: 1
        $x_1_2 = {4c 56 5f 47 52 4f 55 50 00 48 65 61 64 65 72 73 00 42 61 73 65 43 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 72 6f 6e 7a 65 00 53 69 6c 76 65 72 00 47 6f 6c 64 00 50 6c 61 74 69 6e 75 6d 00 44 69 61 6d 6f 6e 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {13 0e 11 0e 16 1f 58 9d 11 0e 17 1f 30 9d 11 0e 18 1f 58 9d 11 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_A_2147686450_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.A"
        threat_id = "2147686450"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NanoCore Client.exe" ascii //weight: 10
        $x_1_2 = {43 6f 6e 6e 65 63 74 44 6f 6e 65 00 43 72 65 61 74 65 50 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 61 73 65 43 6f 6d 6d 61 6e 64 00 44 65 62 75 67 54 79 70 65 00 46 69 6c 65 52 65 73 70 6f 6e 73 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 69 6c 65 44 61 74 61 00 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 6f 73 74 44 61 74 61 00 50 6c 75 67 69 6e 44 65 74 61 69 6c 73 00 50 6c 75 67 69 6e 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_10_6 = {06 1a 1f 0d 9c 06 1b 1f 15 9c 06 1c 1f 22 9c 06 1d 1f 37 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Noancooe_B_2147686469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.B"
        threat_id = "2147686469"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 65 43 68 61 6e 67 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 6e 64 54 6f 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_B_2147686469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.B"
        threat_id = "2147686469"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Client logging has initialized" wide //weight: 1
        $x_1_2 = "Connecting to {0}:{1}.." wide //weight: 1
        $x_1_3 = "Closing {0:N0} pipes.." wide //weight: 1
        $x_1_4 = "RC_DATA" wide //weight: 1
        $x_1_5 = "NanoCore Client.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_C_2147689948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.C"
        threat_id = "2147689948"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NanoCore.ClientPluginHost" ascii //weight: 1
        $x_1_2 = {07 1f 0b 58 06 1d 58 61 d2 ?? 2d 1d 26 02 16 91 02 18 91 1e 62 60 08 19 62 58 0d 16 13 04 16 13 05 2b 4f 0a 2b d3 0b 2b d7}  //weight: 1, accuracy: Low
        $x_1_3 = {06 1f 14 58 18 2d 03 26 2b 03 0a 2b 00 06 07 31 df}  //weight: 1, accuracy: High
        $x_1_4 = {11 05 17 5f 2d 15 09 20 fd 43 03 00 5a 20 c3 9e 26 00 58 0d 09 1f 10 64 d1 13 04 11 04 d2 13 06 11 04 1e 63 d1 13 04 03 11 05 91 13 07 03 11 05 11 07 06 61}  //weight: 1, accuracy: High
        $x_1_5 = "NanoCore Client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_MSIL_Noancooe_C_2147689948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.C"
        threat_id = "2147689948"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x5368656C6C457865637574652846696C6547657453686F72744E616D65282461636363636363292C20272F41" wide //weight: 1
        $x_1_2 = "RC4 ( \"0x2EDF3CDF61CE2801A37A8DE3B39D111F0719CD152DD1DF58EE15EBE0FB83" wide //weight: 1
        $x_1_3 = "#NoTrayIcon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_A_2147692639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.A!!Noancooe.gen!A"
        threat_id = "2147692639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "Noancooe: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 1a 1f 0d 9c 06 1b 1f 15 9c 06 1c 1f 22 9c 06 1d 1f 37 9c}  //weight: 10, accuracy: High
        $x_10_2 = "NanoCore Client.exe" ascii //weight: 10
        $x_1_3 = {43 6f 6e 6e 65 63 74 44 6f 6e 65 00 43 72 65 61 74 65 50 69 70 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 61 73 65 43 6f 6d 6d 61 6e 64 00 44 65 62 75 67 54 79 70 65 00 46 69 6c 65 52 65 73 70 6f 6e 73 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 69 6c 65 44 61 74 61 00 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {48 6f 73 74 44 61 74 61 00 50 6c 75 67 69 6e 44 65 74 61 69 6c 73 00 50 6c 75 67 69 6e 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Noancooe_B_2147692640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.B!!Noancooe.gen!A"
        threat_id = "2147692640"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "Noancooe: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Client logging has initialized" wide //weight: 1
        $x_1_2 = "Connecting to {0}:{1}.." wide //weight: 1
        $x_1_3 = "Closing {0:N0} pipes.." wide //weight: 1
        $x_1_4 = "RC_DATA" wide //weight: 1
        $x_1_5 = "NanoCore Client.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Noancooe_C_2147692641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.C!!Noancooe.gen!A"
        threat_id = "2147692641"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        info = "Noancooe: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NanoCore.ClientPluginHost" ascii //weight: 1
        $x_1_2 = {07 1f 0b 58 06 1d 58 61 d2 ?? 2d 1d 26 02 16 91 02 18 91 1e 62 60 08 19 62 58 0d 16 13 04 16 13 05 2b 4f 0a 2b d3 0b 2b d7}  //weight: 1, accuracy: Low
        $x_1_3 = {06 1f 14 58 18 2d 03 26 2b 03 0a 2b 00 06 07 31 df}  //weight: 1, accuracy: High
        $x_1_4 = {11 05 17 5f 2d 15 09 20 fd 43 03 00 5a 20 c3 9e 26 00 58 0d 09 1f 10 64 d1 13 04 11 04 d2 13 06 11 04 1e 63 d1 13 04 03 11 05 91 13 07 03 11 05 11 07 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_MSIL_Noancooe_D_2147694467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Noancooe.D"
        threat_id = "2147694467"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noancooe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 6f 09 00 00 0a 74 01 00 00 1b 0a 16 0b 2b 15 7e [0-4] 06 07 91 1f [0-1] 61 d2 6f 0a 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 e3 16 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {74 14 00 00 01 6f 2d 00 00 0a [0-1] 9a 6f 2e 00 00 0a [0-1] 9a 0a 06 74 22 00 00 01 14 14 6f 2f 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 0b 00 00 0a 28 0c 00 00 0a 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

