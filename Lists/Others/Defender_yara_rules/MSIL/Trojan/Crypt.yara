rule Trojan_MSIL_Crypt_V_2147743791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.V!MTB"
        threat_id = "2147743791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 07 7b ?? ?? ?? 04 a2 25 17 07 7b ?? ?? ?? 04 a2 25 18 07 7b ?? ?? ?? 04 a2 25 19 07 7b ?? ?? ?? 04 a2 25 1a 07 7b ?? ?? ?? 04 a2 25 1b 07 7b ?? ?? ?? 04 a2 25 1c 07 7b ?? ?? ?? 04 a2 25 1d 07 7b ?? ?? ?? 04 a2 25 1e 07 7b ?? ?? ?? 04 a2 28 ?? ?? ?? 0a a2 a2 6f ?? ?? ?? 0a 26 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Rock_Paper_Scissors" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crypt_AC_2147789436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.AC!MTB"
        threat_id = "2147789436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TRCoManagementSystem.exe" wide //weight: 1
        $x_1_2 = "EICANotifications" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "ProjectData" ascii //weight: 1
        $x_1_5 = "_txtPhone" ascii //weight: 1
        $x_1_6 = "GetResourceString" ascii //weight: 1
        $x_1_7 = "get_StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crypt_MA_2147810506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.MA!MTB"
        threat_id = "2147810506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 1f f8 6a 18 6f ?? ?? ?? 0a 26 06 28 ?? ?? ?? 06 13 05 06 11 05 65 1e 6a 59 17 6f ?? ?? ?? 0a 26 1b 8d ?? 00 00 01 13 06 06 11 06 16 1b 6f ?? ?? ?? 0a 26 73 ?? 00 00 06 25 11 06 6f ?? ?? ?? 06 06 28 ?? ?? ?? 06 13 07 06 08 11 05 11 07 14 6f ?? ?? ?? 06 06 6f ?? ?? ?? 0a 08 16 6a 16 6f ?? ?? ?? 0a 26 08 28 ?? ?? ?? 06 80 ?? 00 00 04 7f ?? ?? ?? 04 7b ?? ?? ?? 04 2c 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Kill" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "GetProcesses" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "2a86c7c2-3153-40ac-a264-405cca3623bb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crypt_MB_2147811262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.MB!MTB"
        threat_id = "2147811262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9a749337-3390-4440-8a8f-17c88b76b3b6" ascii //weight: 1
        $x_1_2 = "P2PKutsweulvbSiHBS" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "huddLohBK1" ascii //weight: 1
        $x_1_6 = "$$method0x6000317-1" ascii //weight: 1
        $x_1_7 = "$$method0x6000332-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crypt_PGAB_2147949980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.PGAB!MTB"
        threat_id = "2147949980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 2c 06 1a 62 07 58 0c 02 7b 09 00 00 04 08 8f 04 00 00 02 28 07 00 00 06 02 7b 0a 00 00 04 08 8f 04 00 00 02 28 07 00 00 06 07 17 58 0b 07 02 7b 1a 00 00 04 36 cb}  //weight: 5, accuracy: High
        $x_5_2 = {11 05 11 0a 8f ?? 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ?? 00 00 00 5f 2d 0b 08 08 5a 20 ?? 5c 8a 00 6a 5e 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crypt_NB_2147952133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crypt.NB!MTB"
        threat_id = "2147952133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 00 65 4f fe 0e 05 00 fe 0d 05 00 00 48 68 39 00 00 00 00 02 73 22 00 00 0a 0a 38 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {07 08 6f 25 00 00 0a 08 6f 26 00 00 0a 0d dd 76 01 00 00 20 01 00 4e 0d fe 0e 05 00 fe 0d 05 00 00 48 68 d3 13 04 38 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "msvsmon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

