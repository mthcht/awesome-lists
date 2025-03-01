rule Backdoor_MSIL_QuasarRAT_YA_2147735339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRAT.YA!MTB"
        threat_id = "2147735339"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\QuasarRAT-master\\" ascii //weight: 1
        $x_1_2 = "xClient.Core.Recovery.Browsers" ascii //weight: 1
        $x_1_3 = "xClient.Core.Recovery.FtpClients" ascii //weight: 1
        $x_1_4 = "GetSavedPasswords" ascii //weight: 1
        $x_1_5 = "passPhrase" ascii //weight: 1
        $x_1_6 = "frmBlockScreen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_QuasarRAT_A_2147835969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRAT.A!MTB"
        threat_id = "2147835969"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 17 2d 01 00 02 17 59 45 03 00 00 00 02 00 00 00 1b 00 00 00 12 00 00 00 2b 28 04 14 06 05 14 14 14 16 28 ?? 00 00 0a 0b 2b 1c 02 8c ?? 00 00 01 0b 2b 13 04 14 06 05 14 14 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetProcessesByName" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "LoadLibrary" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_QuasarRAT_C_2147837519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRAT.C!MTB"
        threat_id = "2147837519"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f ?? 5d 91 61 28 ?? 00 00 0a 06 08 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 08 15 58}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 25 16 1f ?? 9d 6f 05 00 00 04 17 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_QuasarRAT_D_2147837520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRAT.D!MTB"
        threat_id = "2147837520"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f ?? 9d 6f ?? 00 00 0a 06 00 00 00 0a 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {07 11 06 06 11 06 9a 1f ?? 28 ?? 00 00 0a 9c 11 06 17 58}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 25 16 1f ?? 9d 6f ?? 00 00 0a 06 00 00 00 04 17 8d}  //weight: 2, accuracy: Low
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetExportedTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_QuasarRAT_F_2147909822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QuasarRAT.F!MTB"
        threat_id = "2147909822"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ping -n 20 localhost > nul" wide //weight: 2
        $x_2_2 = "{0}d : {1}h : {2}m : {3}s" wide //weight: 2
        $x_2_3 = "URL=file:///" wide //weight: 2
        $x_2_4 = "User: {0}{3}Pass: {1}{3}Host: {2}" wide //weight: 2
        $x_2_5 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

