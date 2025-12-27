rule Trojan_MSIL_RevengeRAT_DA_2147773113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.DA!MTB"
        threat_id = "2147773113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7e1aa602-16dc-451a-8e54-17c9f959a19c" ascii //weight: 1
        $x_1_2 = "ImprovPose.Properties.Resources" ascii //weight: 1
        $x_1_3 = "tensorflow.org/docs" ascii //weight: 1
        $x_1_4 = "Train model" ascii //weight: 1
        $x_1_5 = "TryParse" ascii //weight: 1
        $x_1_6 = "Clone" ascii //weight: 1
        $x_1_7 = "DictionaryEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_DC_2147783083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.DC!MTB"
        threat_id = "2147783083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1e 5b 8d 2a 00 00 01 0b 16 0d 2b 19 00 07 09 06 09 1e 5a 1e 6f ?? ?? ?? 0a 18 28 ?? ?? ?? 0a 9c 00 09 17 58 0d 09 07 8e 69 17 59 fe 02 16 fe 01 13 04 11 04 2d d6}  //weight: 10, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "ToByte" ascii //weight: 1
        $x_1_4 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_DB_2147783520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.DB!MTB"
        threat_id = "2147783520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 13 04 17 13 05 2b 41 08 07 33 02 17 0c 03 08 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 09 02 11 05 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 07 d8 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 04 31 b9}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_DD_2147845630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.DD!MTB"
        threat_id = "2147845630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 20 4e 00 00 28 ?? ?? ?? 0a 00 20 20 4e 00 00 28 ?? ?? ?? 0a 00 20 20 4e 00 00 28 ?? ?? ?? 0a 00 20 20 4e 00 00 28 ?? ?? ?? 0a 00 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 1f 2d 9d 28 ?? ?? ?? 0a 17 9a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 1f 2d 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_A_2147848600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.A!MTB"
        threat_id = "2147848600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 14 1a 8d ?? 00 00 01 13 07 11 07 16 28 ?? 00 00 06 6f ?? 00 00 0a a2 11 07 17 72 ?? 00 00 70 a2 11 07 18 11 01 a2 11 07 19 16 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_B_2147849721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.B!MTB"
        threat_id = "2147849721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RV-Infect-Lime" ascii //weight: 2
        $x_2_2 = "dyx04pqthe3.resources" ascii //weight: 2
        $x_2_3 = "volcfrltSAeXKoSqkxPRHXwokwkK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_NRR_2147891692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.NRR!MTB"
        threat_id = "2147891692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 58 00 00 0a 25 26 73 ?? 00 00 0a 6f ?? 00 00 0a 25 26 1f 24 28 ?? 00 00 06 25 26 1f 35 28 ?? 00 00 06 25 26 28 ?? 00 00 06 25 26 28 ?? 00 00 0a 25 26}  //weight: 5, accuracy: Low
        $x_1_2 = "AesOnuyeGa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_D_2147895563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.D!MTB"
        threat_id = "2147895563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 09 74 ?? 00 00 01 a2 25 13 07 14 14 17 8d ?? 00 00 01 25 16 17 9c 25}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_E_2147904612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.E!MTB"
        threat_id = "2147904612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319" wide //weight: 2
        $x_2_5 = "C:\\Windows\\SysWOW64\\cmd.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RevengeRAT_NR_2147933075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevengeRAT.NR!MTB"
        threat_id = "2147933075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 07 09 16 20 00 01 00 00 6f 52 06 00 0a 13 04 07 09 16 11 04 6f 0c 05 00 0a 00 11 05 11 04 d6 13 05 11 06 6f 50 06 00 0a 11 05 6a fe 04 13 09 11 09 2c 1e 02 7b 3e 08 00 04 13 0a 11 0a 2c 0f 11 0a 11 06 6f 50 06 00 0a 6f 3a 13 00 06}  //weight: 3, accuracy: High
        $x_2_2 = {7b 40 08 00 04 13 0d 11 0d 2c 08 11 0d 6f 42 13 00 06 00 17 0a de 3d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

