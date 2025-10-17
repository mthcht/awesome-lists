rule Trojan_MSIL_PureLogsStealer_APL_2147899424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.APL!MTB"
        threat_id = "2147899424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 ?? 00 00 0a 13 09 11 09 08 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_APL_2147899424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.APL!MTB"
        threat_id = "2147899424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 0c 08 6f ?? 00 00 0a 72 ?? 05 00 70 6f ?? 00 00 0a 26 08 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "\\AppData\\Local\\Temporary Projects\\WindowsFormsApp1\\obj\\Debug\\iTalk.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_A_2147907671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.A!MTB"
        threat_id = "2147907671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_B_2147907965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.B!MTB"
        threat_id = "2147907965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 06 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_C_2147920554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.C!MTB"
        threat_id = "2147920554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 14 14 14 6f ?? ?? 00 0a 26 20}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_AYA_2147925542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.AYA!MTB"
        threat_id = "2147925542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$6e19b582-8c18-4345-8815-cbc3a39d8caa" ascii //weight: 2
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "m8DCCDDF7720FD0C" ascii //weight: 1
        $x_1_4 = "6d9d513055ae746f0f" ascii //weight: 1
        $x_1_5 = "xe87342ae14514b0f8263a61d5bbd2626" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogsStealer_ZZM_2147955365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogsStealer.ZZM!MTB"
        threat_id = "2147955365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 20 7b 11 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 20 48 11 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 2b 29 11 06 1f 0f 61 13 06 11 06 1f 0e 58 45 06 00 00 00 0b 00 00 00 12 00 00 00 23 00 00 00 2d 00 00 00 34 00 00 00 42 00 00 00 1f 19 28 ?? 00 00 06 13 06 2b cc 00 1f f9 13 06 2b c5 09 6f ?? 00 00 0a 1f 1d 28 ?? 00 00 06 13 06 2b b4}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

