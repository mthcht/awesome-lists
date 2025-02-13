rule Trojan_MSIL_DarkStealer_DB_2147773115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.DB!MTB"
        threat_id = "2147773115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$512e913d-1c5a-44d1-bc7e-a7ce5cfcdd25" ascii //weight: 1
        $x_1_2 = "CS.My.Resources" ascii //weight: 1
        $x_1_3 = "CS.frmParish.resources" ascii //weight: 1
        $x_1_4 = "Masaka" ascii //weight: 1
        $x_1_5 = "Parish Manager" ascii //weight: 1
        $x_1_6 = "Matrimony Marriage" ascii //weight: 1
        $x_1_7 = "CS.Report1.rdlc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_NU_2147819175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.NU!MTB"
        threat_id = "2147819175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 b7 a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "$f1515ad9-4b12-4820-a79c-311d5e9f9c46" ascii //weight: 1
        $x_1_3 = "TemporalToolkit.Properties.Resources" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_RPN_2147821971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.RPN!MTB"
        threat_id = "2147821971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 1f 00 00 0a 03 04 17 58 08 5d 91 28 20 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_RPN_2147821971_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.RPN!MTB"
        threat_id = "2147821971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "GetString" wide //weight: 1
        $x_1_3 = "Length" wide //weight: 1
        $x_1_4 = "config.ini" wide //weight: 1
        $x_1_5 = "log.txt" wide //weight: 1
        $x_1_6 = "Could not set keyboard hook" wide //weight: 1
        $x_1_7 = "Start Recording" wide //weight: 1
        $x_1_8 = "\\\\screens\\\\misc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_NI_2147823618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.NI!MTB"
        threat_id = "2147823618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 02 26 16 00 0f 00 28 ?? 00 00 06 25 26 0f 01 28 ?? 00 00 06 25 26 d0 01 00 00 1b 28 ?? 00 00 0a 25 26 28 ?? 00 00 0a 25 26 a5 01 00 00 1b 0a 38 00 00 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {57 b5 a2 1d 09 0f 00 00 00 00 00 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_RHB_2147906792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.RHB!MTB"
        threat_id = "2147906792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "atmanng.no-ip.info" wide //weight: 1
        $x_1_2 = "SelectServer" wide //weight: 1
        $x_1_3 = "data_password" ascii //weight: 1
        $x_1_4 = "Order by Accounts.System" wide //weight: 1
        $x_1_5 = "ChineseName From UserList" wide //weight: 1
        $x_1_6 = "WFCL.SelectServer.resources" ascii //weight: 1
        $x_1_7 = "SyncData(AN-NAS)" ascii //weight: 1
        $x_1_8 = "AN-Server" ascii //weight: 1
        $x_1_9 = "WFCL.pdb" ascii //weight: 1
        $x_2_10 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 ?? ?? ?? ?? ?? 00 76 02 ?? ?? ?? ?? ?? ?? ?? 05 00 00 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkStealer_ASJ_2147919719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkStealer.ASJ!MTB"
        threat_id = "2147919719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 16 13 05 08 11 05 09 11 05 9a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 11 05 17 d6 13 05 11 05 1b 31 e1 1f 66 8d ?? 00 00 01 13 04 16 13 06 11 04 11 06 20 ff 00 00 00 9c 11 06 17 d6 13 06 11 06 1b 31 eb}  //weight: 3, accuracy: Low
        $x_1_2 = {11 04 11 07 08 11 07 1c 5d 91 9c 11 07 17 d6 13 07 11 07 1f 65 31 e9}  //weight: 1, accuracy: High
        $x_1_3 = "192.168.100.51\\Public\\MapDrive\\Public" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

