rule Trojan_MSIL_SnakeKeylogger_MK_2147771840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MK!MTB"
        threat_id = "2147771840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SNAKE-KEYLOGGER" ascii //weight: 10
        $x_10_2 = {53 2d 2d 2d 2d 2d 2d 2d 2d 4e 2d 2d 2d 2d 2d 2d 2d 2d 41 2d 2d 2d 2d 2d 2d 2d 2d 4b 2d 2d 2d 2d 2d 2d 2d 2d 45 [0-22] 53 4e 41 4b 45 2d 4b 45 59 4c 4f 47 47 45 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MK_2147771840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MK!MTB"
        threat_id = "2147771840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SNAKE-KEYLOGGER" ascii //weight: 10
        $x_10_2 = "S--------N--------A--------K--------E" ascii //weight: 10
        $x_1_3 = "CredentialModel" ascii //weight: 1
        $x_1_4 = "get_Username" ascii //weight: 1
        $x_1_5 = "set_Username" ascii //weight: 1
        $x_1_6 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MK_2147771840_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MK!MTB"
        threat_id = "2147771840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0d 09 07 16 07 8e 69 6f 0d 00 00 0a 13 04 28 06 00 00 0a 11 04 6f 0e 00 00 0a 13 05 dd 0d 00 00 00 26 7e 0f 00 00 0a 13 05 dd}  //weight: 5, accuracy: High
        $x_2_2 = "Expansion_Manager_Waniur.exe" wide //weight: 2
        $x_2_3 = "TTRDZBWIimjJZrG" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DA_2147777831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DA!MTB"
        threat_id = "2147777831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$478c8cb0-145b-4c23-a71a-432a78caa4db" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "Calculator_2.Properties.Resources" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
        $x_1_8 = "get_Instance" ascii //weight: 1
        $x_1_9 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_MK1_2147782602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MK1!MTB"
        threat_id = "2147782602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Snake Keylogger" ascii //weight: 10
        $x_10_2 = "\\SnakeKeylogger" ascii //weight: 10
        $x_10_3 = "\\Login Data" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DB_2147784153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DB!MTB"
        threat_id = "2147784153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//test.co/tst" ascii //weight: 1
        $x_1_2 = "WebHeaderCollection" ascii //weight: 1
        $x_1_3 = "NameValueCollection" ascii //weight: 1
        $x_1_4 = "My Test Header Value" ascii //weight: 1
        $x_1_5 = "ForgotModel" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
        $x_1_7 = "hello" ascii //weight: 1
        $x_1_8 = "world" ascii //weight: 1
        $x_1_9 = "Discord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DC_2147784157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DC!MTB"
        threat_id = "2147784157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GameBox.Logo.resources" ascii //weight: 1
        $x_1_2 = "GameBox.Properties" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "openKeyboard" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "get_Key" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DD_2147784158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DD!MTB"
        threat_id = "2147784158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$b6863295-2878-4d4a-9ebb-b0bd54216003" ascii //weight: 20
        $x_1_2 = "AlarmClock.Resources.resources" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DE_2147784682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DE!MTB"
        threat_id = "2147784682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d0d2cfbb-c06c-4dbe-af8a-ae0fbb6a2db0" ascii //weight: 20
        $x_1_2 = "AlarmClock.Resources.resources" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DF_2147784684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DF!MTB"
        threat_id = "2147784684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinFormsSyntaxHighlighter" ascii //weight: 1
        $x_1_2 = "egolds" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "You are Awesome" ascii //weight: 1
        $x_1_5 = "Convert" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DG_2147785190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DG!MTB"
        threat_id = "2147785190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {49 4d 47 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_20_2 = {49 4d 47 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 43 6f 6e 6e 65 63 74 69 6f 6e 73 2e 53 74 61 74 65 2e 72 65 73 6f 75 72 63 65 73}  //weight: 20, accuracy: Low
        $x_20_3 = {46 4c 5f 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_20_4 = {46 4c 5f 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 44 69 63 74 69 6f 6e 61 72 69 65 73}  //weight: 20, accuracy: Low
        $x_20_5 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-3] 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_20_6 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-3] 2e 44 65 66 69 6e 69 74 69 6f 6e 73 2e 4d 6f 63 6b 2e 72 65 73 6f 75 72 63 65 73}  //weight: 20, accuracy: Low
        $x_1_7 = "Telegram Desktop" ascii //weight: 1
        $x_1_8 = "Telegram FZ-LLC" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 4 of ($x_1_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DH_2147785191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DH!MTB"
        threat_id = "2147785191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 02 08 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b6 28 ?? ?? ?? 0a 13 04 06 11 04 6f ?? ?? ?? 0a 26 07 03 6f ?? ?? ?? 0a 17 da 33 04}  //weight: 10, accuracy: Low
        $x_1_2 = "GZIDEKKKK" ascii //weight: 1
        $x_1_3 = "XOR_Decrypt" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DI_2147786213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DI!MTB"
        threat_id = "2147786213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "74"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "AZZZZZZZZZZZZZZZZ23" ascii //weight: 50
        $x_50_2 = "imimimimim" ascii //weight: 50
        $x_20_3 = "XDASXAXAX" ascii //weight: 20
        $x_20_4 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00}  //weight: 20, accuracy: High
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "FromBase64" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "get_X" ascii //weight: 1
        $x_1_9 = "get_Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DJ_2147786214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DJ!MTB"
        threat_id = "2147786214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 02 08 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 d1 28 ?? ?? ?? 0a 13 04 06 11 04 6f ?? ?? ?? 0a 26 07 03 6f ?? ?? ?? 0a 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DK_2147786217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DK!MTB"
        threat_id = "2147786217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SecureLife.My.Resources" ascii //weight: 1
        $x_1_2 = {00 69 69 69 69 69 69 00}  //weight: 1, accuracy: High
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "FromBase64" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DM_2147786438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DM!MTB"
        threat_id = "2147786438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 03 08 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a da 0d 06 09 b6 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 17 d6 0c 00 08 07 fe 02 16 fe 01 13 04 11 04 2d bc}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
        $x_1_6 = "SunDay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DN_2147786439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DN!MTB"
        threat_id = "2147786439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$dbe766d4-f1a1-4895-b46c-18c3b67698b2" ascii //weight: 20
        $x_20_2 = "$0871a5f6-e73f-46ce-9b37-33101c345eec" ascii //weight: 20
        $x_20_3 = "$d8772df3-f022-453c-9533-2bbd2d9dae02" ascii //weight: 20
        $x_20_4 = "$cbb984e9-c82b-4b35-a6f5-c8546b9dafab" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DO_2147786654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DO!MTB"
        threat_id = "2147786654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Portalquiz.Properties.Resources" ascii //weight: 10
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "FromBase64" ascii //weight: 1
        $x_1_4 = "Convert" ascii //weight: 1
        $x_1_5 = "get_Length" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "Concat" ascii //weight: 1
        $x_1_8 = "get_X" ascii //weight: 1
        $x_1_9 = "get_Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DP_2147786655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DP!MTB"
        threat_id = "2147786655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a4e450a1-cd08-40bd-9aae-49dd80df08c5" ascii //weight: 20
        $x_20_2 = "$7beb9122-58b2-4d3b-a044-6f7f3fd6578b" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DQ_2147786760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DQ!MTB"
        threat_id = "2147786760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$08936ef1-8f6c-471c-9d11-7b45284ca4a6" ascii //weight: 20
        $x_20_2 = "$12e4473b-0112-4e2b-9019-3dfc00f2a608" ascii //weight: 20
        $x_20_3 = "$6f4d5046-7aa8-48de-b322-955fe5d121c8" ascii //weight: 20
        $x_20_4 = "$3786c6e8-37c0-45aa-a5a1-5fdc696511d8" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DR_2147787202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DR!MTB"
        threat_id = "2147787202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$2a65605b-6c4f-447f-9099-6e8a8220b62b" ascii //weight: 20
        $x_20_2 = "$07f71125-719a-4399-9209-998c928245d3" ascii //weight: 20
        $x_20_3 = "$41488171-5017-41e2-9d48-db66764c0ccb" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DS_2147787203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DS!MTB"
        threat_id = "2147787203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$d800990a-1399-4613-815f-f80a98a3e4be" ascii //weight: 20
        $x_20_2 = "$66af0239-7820-4efc-a120-2e04e262061a" ascii //weight: 20
        $x_20_3 = "$b119f64e-2c67-42fc-b198-6d4e0923bd7f" ascii //weight: 20
        $x_20_4 = "$309f22c7-5529-473f-8b30-d2e892711709" ascii //weight: 20
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_9 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggingModes" ascii //weight: 1
        $x_1_12 = "FromBase64String" ascii //weight: 1
        $x_1_13 = "CreateInstance" ascii //weight: 1
        $x_1_14 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DT_2147787435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DT!MTB"
        threat_id = "2147787435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$3e67dcd5-3edb-4e24-9eb8-93f66f9f1589" ascii //weight: 20
        $x_20_2 = "$954de79c-63c4-4015-8417-d46588f7cb0f" ascii //weight: 20
        $x_20_3 = "$1f6c79a8-526a-428b-b38f-94141c6ce811" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_DV_2147787833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DV!MTB"
        threat_id = "2147787833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeatSaverDownloader" ascii //weight: 1
        $x_1_2 = "Log.txt" ascii //weight: 1
        $x_1_3 = "KeyCollection" ascii //weight: 1
        $x_1_4 = "get_Keys" ascii //weight: 1
        $x_1_5 = "DragonForce" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DX_2147788238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DX!MTB"
        threat_id = "2147788238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FDDDDDDF" ascii //weight: 1
        $x_1_2 = "IIIIIuasIIIIII" ascii //weight: 1
        $x_1_3 = "TripleDES" ascii //weight: 1
        $x_1_4 = "RunPowerShell" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DY_2147788239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DY!MTB"
        threat_id = "2147788239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Millionare.Properties.Resources" ascii //weight: 1
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "DontLetUserLogin" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DZ_2147788432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DZ!MTB"
        threat_id = "2147788432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B________________________B" ascii //weight: 1
        $x_1_2 = "S____________________________S" ascii //weight: 1
        $x_1_3 = "DialogsLib" ascii //weight: 1
        $x_1_4 = "KeyEventArgs" ascii //weight: 1
        $x_1_5 = "KeyEventHandler" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "SuspendLayout" ascii //weight: 1
        $x_1_8 = "ToByte" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EA_2147788433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EA!MTB"
        threat_id = "2147788433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$6d53d846-7437-4ca0-bee0-aa292eecd51a" ascii //weight: 10
        $x_1_2 = "DialogsLib" ascii //weight: 1
        $x_1_3 = {00 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_4 = "re.txt" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_EB_2147788481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EB!MTB"
        threat_id = "2147788481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0b 14 0c 28 ?? ?? ?? 06 74 06 00 00 1b 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 08 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "B________________________B" ascii //weight: 1
        $x_1_3 = "S____________________________S" ascii //weight: 1
        $x_1_4 = "DialogsLib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EC_2147788482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EC!MTB"
        threat_id = "2147788482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$716c0da9-151e-4f62-819f-b140eee1fbf8" ascii //weight: 10
        $x_1_2 = "National Shirt Shop" ascii //weight: 1
        $x_1_3 = "Congratulations! You won" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ED_2147789029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ED!MTB"
        threat_id = "2147789029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {14 0b 14 0c 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 08 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 0a 2b 00 06 2a}  //weight: 20, accuracy: Low
        $x_5_2 = "$f31993cd-d79c-4ff9-898d-abb99aa3f0c2" ascii //weight: 5
        $x_5_3 = "$64b23961-ced7-48ee-a643-9ab35a655ee3" ascii //weight: 5
        $x_5_4 = "$EC344FFB-4516-450D-BF74-67D9A6033811" ascii //weight: 5
        $x_1_5 = "W__________W" ascii //weight: 1
        $x_1_6 = "X__________X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_EE_2147789030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EE!MTB"
        threat_id = "2147789030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {14 0b 14 0c 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 08 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 0a 2b 00 06 2a}  //weight: 20, accuracy: Low
        $x_5_2 = "$c840a6a5-6310-468b-8ccc-894fe4d107a6" ascii //weight: 5
        $x_1_3 = "W__________W" ascii //weight: 1
        $x_1_4 = "X__________X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EF_2147789031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EF!MTB"
        threat_id = "2147789031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "W__________W" ascii //weight: 10
        $x_10_2 = "X__________X" ascii //weight: 10
        $x_1_3 = "KeyEventHandler" ascii //weight: 1
        $x_1_4 = "MouseEventHandler" ascii //weight: 1
        $x_1_5 = "KeyEventArgs" ascii //weight: 1
        $x_1_6 = "MouseEventArgs" ascii //weight: 1
        $x_1_7 = "OnKeyPress" ascii //weight: 1
        $x_1_8 = "add_MouseClick" ascii //weight: 1
        $x_1_9 = "get_Keys" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EG_2147789172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EG!MTB"
        threat_id = "2147789172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {14 0b 14 0c 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 08 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 0a 2b 00 06 2a}  //weight: 20, accuracy: Low
        $x_1_2 = "X_X_X_X_A_A_A_A_S_S_S_S" ascii //weight: 1
        $x_1_3 = "W__________W" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EH_2147789530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EH!MTB"
        threat_id = "2147789530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$e06f2b46-7028-4587-8c8c-a4ce9783bcb8" ascii //weight: 10
        $x_1_2 = {00 58 58 58 58 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_3 = "Md5Decrypt" ascii //weight: 1
        $x_1_4 = "GangBang" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EI_2147789531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EI!MTB"
        threat_id = "2147789531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {1b 0a 06 17 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 06 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 06 28 ?? ?? ?? 0a 26 06 2a}  //weight: 20, accuracy: Low
        $x_1_2 = "X_X_X_X_A_A_A_A_S_S_S_S" ascii //weight: 1
        $x_1_3 = "W__________W" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EJ_2147789533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EJ!MTB"
        threat_id = "2147789533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$11e448c6-01e6-4ce7-acd6-dd831a924d01" ascii //weight: 10
        $x_1_2 = "X_X_X_X_A_A_A_A_S_S_S_S" ascii //weight: 1
        $x_1_3 = "W__________W" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EK_2147793076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EK!MTB"
        threat_id = "2147793076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {1b 0a 06 17 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 06 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 06 28 ?? ?? ?? 0a 26 06}  //weight: 20, accuracy: Low
        $x_1_2 = "O_0_0_0_0_0_0_0_0_0_0_0" ascii //weight: 1
        $x_1_3 = "O_O_O_O_O_O_O_O_O_O" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EL_2147793133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EL!MTB"
        threat_id = "2147793133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tank90" ascii //weight: 1
        $x_1_2 = "tank_game_over.png" ascii //weight: 1
        $x_1_3 = {00 4f 4f 4f 4f 4f 00}  //weight: 1, accuracy: High
        $x_1_4 = "FromBase64" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Activator" ascii //weight: 1
        $x_1_7 = "GetMethod" ascii //weight: 1
        $x_1_8 = "get_Y" ascii //weight: 1
        $x_1_9 = "get_X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EM_2147793134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EM!MTB"
        threat_id = "2147793134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$3e1f0486-a4a8-45d4-b036-f0acd8bcbdf7" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_EN_2147793310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EN!MTB"
        threat_id = "2147793310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {1b 0a 06 17 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 06 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 06 28 ?? ?? ?? 0a 26 06}  //weight: 20, accuracy: Low
        $x_1_2 = "FT_FT1" ascii //weight: 1
        $x_1_3 = "FT_FT2" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EO_2147793311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EO!MTB"
        threat_id = "2147793311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$4629d8b2-b162-44a9-a207-f2b0b42234c5" ascii //weight: 20
        $x_1_2 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_3 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_SST_2147793388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SST!MTB"
        threat_id = "2147793388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$$method0x6000022-1" ascii //weight: 1
        $x_1_2 = "BabelObfuscatorAttribute" ascii //weight: 1
        $x_1_3 = "fsafafwwwwwwwwaf" ascii //weight: 1
        $x_1_4 = "BabelAttribute" ascii //weight: 1
        $x_1_5 = "SuppressIldasmAttribute" ascii //weight: 1
        $x_1_6 = "_stackTraceString" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "CanonicalizeAsFilePath" ascii //weight: 1
        $x_1_9 = "CryptoStream" ascii //weight: 1
        $x_1_10 = "PA_NoPlatform" ascii //weight: 1
        $x_1_11 = "NineRays.Obfuscator.Evaluation" ascii //weight: 1
        $x_1_12 = "ModuleBuilder" ascii //weight: 1
        $x_1_13 = "BitConverter" ascii //weight: 1
        $x_1_14 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_15 = "198 Protector V2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SST_2147793388_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SST!MTB"
        threat_id = "2147793388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebClient" ascii //weight: 1
        $x_1_2 = "get_ExecutablePath" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "ResumeLayout" ascii //weight: 1
        $x_1_6 = "StringBuilder" ascii //weight: 1
        $x_1_7 = "198-Protector" ascii //weight: 1
        $x_1_8 = "AsyncCallback" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "Assembly" ascii //weight: 1
        $x_1_11 = "SuppressIldasmAttribute" ascii //weight: 1
        $x_1_12 = "HashAlgorithm" ascii //weight: 1
        $x_1_13 = "ICryptoTransform" ascii //weight: 1
        $x_1_14 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_15 = "set_Key" ascii //weight: 1
        $x_1_16 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_17 = "CopyTo" ascii //weight: 1
        $x_1_18 = "ComputeHash" ascii //weight: 1
        $x_1_19 = "Encoding" ascii //weight: 1
        $x_1_20 = "SymmetricAlgorithm" ascii //weight: 1
        $x_30_21 = "SnakeLogger" ascii //weight: 30
        $x_30_22 = "snake crypted" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_30_*) and 8 of ($x_1_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_EP_2147793870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EP!MTB"
        threat_id = "2147793870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c8971c9d-6908-45e5-ae2d-e2befe0c50f2" ascii //weight: 20
        $x_20_2 = "$439dfbe6-fec7-4775-a7a2-cd2546899074" ascii //weight: 20
        $x_20_3 = "$e092b687-6835-4927-bae4-5422b13f6536" ascii //weight: 20
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DebuggingModes" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "CreateInstance" ascii //weight: 1
        $x_1_13 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_MA_2147794213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MA!MTB"
        threat_id = "2147794213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 0d 74 03 00 00 1b 2a 28 ?? 00 00 06 2b e7 6f ?? 00 00 0a 2b ec 25 00 2b 12 72 ?? 00 00 70 7e ?? 00 00 04}  //weight: 2, accuracy: Low
        $x_2_2 = {1e 2c 18 2b 18 2b 1d 2b 22 ?? ?? 09 26 12 00 ?? 2d 07 26 de 2a 2b 1b 2b f4 2b 1a 2b f6 28 ?? 00 00 06 2b e1 28 0f 00 00 06 2b dc 28 10 00 00 06 2b d7 0a 2b e2 28 11 00 00 06 2b df 26 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MA_2147794213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MA!MTB"
        threat_id = "2147794213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 81 00 00 00 20}  //weight: 5, accuracy: High
        $x_2_2 = "BuildEvent.Properties" ascii //weight: 2
        $x_2_3 = "445a98f1-5bfd-4ec9-af3d-bc1c04ec5692" ascii //weight: 2
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SSTR_2147795089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SSTR!MTB"
        threat_id = "2147795089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MMCHIA.exe" ascii //weight: 1
        $x_1_2 = "RegAsm.exe" ascii //weight: 1
        $x_1_3 = "GetString" ascii //weight: 1
        $x_1_4 = "Assembly" ascii //weight: 1
        $x_1_5 = "kernel32.dll" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "hexString" ascii //weight: 1
        $x_1_10 = "FromHexString" ascii //weight: 1
        $x_1_11 = "RawForm" ascii //weight: 1
        $x_1_12 = "00360032003800320037003000340034003900300034002F003800380039003900380031" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NJN_2147799510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NJN!MTB"
        threat_id = "2147799510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "noisreV ylbmessA" ascii //weight: 1
        $x_1_2 = "noisreVtcudorP" ascii //weight: 1
        $x_1_3 = "get_PathAndQuery" ascii //weight: 1
        $x_1_4 = "https://user:password@www.contoso.com:80/Home/Index.htm" ascii //weight: 1
        $x_1_5 = "DnsSafeHost:" ascii //weight: 1
        $x_1_6 = "powershell" ascii //weight: 1
        $x_1_7 = "$d4d36f55-830f-414b-83c3-d7a28d5b65e8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SSU_2147799516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SSU!MTB"
        threat_id = "2147799516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "LINKS_IN_HERE" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "ResumeLayout" ascii //weight: 1
        $x_1_8 = "get_Assembly" ascii //weight: 1
        $x_1_9 = "get_ResourceManager" ascii //weight: 1
        $x_1_10 = "$6e5b9692-f94d-4bd0-b9e7-2852370dedd4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_UYT_2147806246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.UYT!MTB"
        threat_id = "2147806246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Courier New" ascii //weight: 1
        $x_1_2 = "ChickenInvaders" ascii //weight: 1
        $x_1_3 = "LINKS_IN_HERE" ascii //weight: 1
        $x_1_4 = "4D5A90000300000004000000FFFF0000B800000000000000" ascii //weight: 1
        $x_1_5 = "HostExecutionContext" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "get_KeyCode" ascii //weight: 1
        $x_1_8 = "NewLateBinding" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "ResumeLayout" ascii //weight: 1
        $x_1_11 = "ThreadStart" ascii //weight: 1
        $x_1_12 = "ConvertFromUtf32" ascii //weight: 1
        $x_1_13 = "StringBuilder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPD_2147814813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPD!MTB"
        threat_id = "2147814813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 06 6f 25 00 00 0a 0c 12 02 28 26 00 00 0a 23 00 00 00 00 00 00 34 40 fe 04 0b 07 2d e1}  //weight: 1, accuracy: High
        $x_1_2 = "get_Elapsed" ascii //weight: 1
        $x_1_3 = "get_TotalSeconds" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
        $x_1_6 = "TaskDelay" ascii //weight: 1
        $x_1_7 = "ReadBytes" ascii //weight: 1
        $x_1_8 = "Stopwatch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPC_2147815368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPC!MTB"
        threat_id = "2147815368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2c 03 17 2b 03 16 2b 00 2d 03 26 2b 07 28 1a 00 00 0a 2b 00 2a 06 00 20 20 4e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPC_2147815368_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPC!MTB"
        threat_id = "2147815368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "Jpmnvnlm.png" wide //weight: 1
        $x_1_3 = "/c timeout 20" wide //weight: 1
        $x_1_4 = "Exnjdyfmpjsqtbqfgtijh" wide //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "Binder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPC_2147815368_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPC!MTB"
        threat_id = "2147815368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/avatars" wide //weight: 1
        $x_1_2 = "api4.ipify.org" wide //weight: 1
        $x_1_3 = "Mozilla" wide //weight: 1
        $x_1_4 = "Chrome" wide //weight: 1
        $x_1_5 = "Safari" wide //weight: 1
        $x_1_6 = "cookie" wide //weight: 1
        $x_1_7 = "Discord Canary" wide //weight: 1
        $x_1_8 = "Discord PTB" wide //weight: 1
        $x_1_9 = "Opera" wide //weight: 1
        $x_1_10 = "Brave" wide //weight: 1
        $x_1_11 = "Yandex" wide //weight: 1
        $x_1_12 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_13 = "HttpWebResponse" ascii //weight: 1
        $x_1_14 = "FromBase64String" ascii //weight: 1
        $x_1_15 = "GetFolderPath" ascii //weight: 1
        $x_1_16 = "FileStream" ascii //weight: 1
        $x_1_17 = "SpecialFolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPS_2147815610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPS!MTB"
        threat_id = "2147815610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gulnar" ascii //weight: 1
        $x_1_2 = "Mirarmar" ascii //weight: 1
        $x_1_3 = "Hasenda" ascii //weight: 1
        $x_1_4 = "Paradise" ascii //weight: 1
        $x_1_5 = "BootCamp" ascii //weight: 1
        $x_1_6 = "Store" ascii //weight: 1
        $x_1_7 = "Helper_Classes" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "VpnClientWrapper" ascii //weight: 1
        $x_1_11 = "GetExportedTypes" ascii //weight: 1
        $x_1_12 = "VpnConnectService" ascii //weight: 1
        $x_1_13 = "ComputeHash" ascii //weight: 1
        $x_1_14 = "Encoding" ascii //weight: 1
        $x_1_15 = "BigEndianUnicode" ascii //weight: 1
        $x_1_16 = "GetBytes" ascii //weight: 1
        $x_1_17 = "CreateDecryptor" ascii //weight: 1
        $x_1_18 = "TransformFinalBlock" ascii //weight: 1
        $x_1_19 = "Length" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPB_2147815870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPB!MTB"
        threat_id = "2147815870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 75 00 62 00 71 00 74 00 61 00 6e 00 65 00 6f 00 75 00 73 00 73 00 68 00 6f 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-48] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "CreateDelegate" ascii //weight: 1
        $x_1_7 = "GetInvocationList" ascii //weight: 1
        $x_1_8 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPB_2147815870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPB!MTB"
        threat_id = "2147815870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "18.179.111.240" wide //weight: 1
        $x_1_2 = "loader" wide //weight: 1
        $x_1_3 = "uploads" wide //weight: 1
        $x_1_4 = "Gpsepqzx.jpg" wide //weight: 1
        $x_1_5 = "/c timeout 20" wide //weight: 1
        $x_1_6 = "Rftamajnqoqwocdiwfrw.Heasezfvvh" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPB_2147815870_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPB!MTB"
        threat_id = "2147815870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide //weight: 1
        $x_1_2 = "KUzYB8cqvjOmLb1hItJnWLI6Va1qzybfuxr28llf7GgilBWSjMvl4Fo8m" wide //weight: 1
        $x_1_3 = "CaptainBri" ascii //weight: 1
        $x_1_4 = "TickCount" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_6 = "RC4EncryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPB_2147815870_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPB!MTB"
        threat_id = "2147815870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-80] 43 00 68 00 72 00 6f 00 6d 00 65 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
        $x_1_4 = "DisableTaskMgr" wide //weight: 1
        $x_1_5 = "vmware" wide //weight: 1
        $x_1_6 = "VirtualBox" wide //weight: 1
        $x_1_7 = "Password Grabber is disabled" wide //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "ToBase64String" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
        $x_1_11 = "DownloadFile" ascii //weight: 1
        $x_1_12 = "Sleep" ascii //weight: 1
        $x_1_13 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPU_2147816518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPU!MTB"
        threat_id = "2147816518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "Jjrtljsc.png" wide //weight: 1
        $x_1_3 = "Ctaepaqwxsyw" wide //weight: 1
        $x_1_4 = "WebResponse" ascii //weight: 1
        $x_1_5 = "Stopwatch" ascii //weight: 1
        $x_1_6 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPV_2147816519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPV!MTB"
        threat_id = "2147816519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HABBHH5C5474GGO7S78GGZ84O1QG58P455HOH8DG5ZCA8RCRE9" wide //weight: 1
        $x_1_2 = "MON_TEXTE_A_MODIFIER" wide //weight: 1
        $x_1_3 = "EntryPoint" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "Decrypt_aes" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "CallByName" ascii //weight: 1
        $x_1_9 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_10 = "GetString" ascii //weight: 1
        $x_1_11 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPI_2147817288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPI!MTB"
        threat_id = "2147817288"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-160] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "GetType" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "Assembly" ascii //weight: 1
        $x_1_5 = "WaitOne" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "WriteAdapter" ascii //weight: 1
        $x_1_9 = "CheckAdapter" ascii //weight: 1
        $x_1_10 = "CallAdapter" ascii //weight: 1
        $x_1_11 = "TestAdapter" ascii //weight: 1
        $x_1_12 = "CollectAdapter" ascii //weight: 1
        $x_1_13 = "Skype Technologies S.A." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPJ_2147817289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPJ!MTB"
        threat_id = "2147817289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 00 34 00 34 00 2e 00 31 00 32 00 36 00 2e 00 31 00 35 00 39 00 2e 00 31 00 30 00 32 00 3a 00 38 00 30 00 38 00 30 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 [0-80] 2e 00 70 00 6e 00 67 00}  //weight: 10, accuracy: Low
        $x_10_2 = {31 00 34 00 34 00 2e 00 31 00 32 00 36 00 2e 00 31 00 35 00 39 00 2e 00 31 00 30 00 32 00 3a 00 38 00 30 00 38 00 30 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 [0-80] 2e 00 6a 00 70 00 67 00}  //weight: 10, accuracy: Low
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "WebResponse" ascii //weight: 1
        $x_1_7 = "CopyTo" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "System.Threading" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_RPM_2147817552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPM!MTB"
        threat_id = "2147817552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EGE5YEAIX5HCF54GZ8H484" wide //weight: 1
        $x_1_2 = "beamUI" wide //weight: 1
        $x_1_3 = "mainPorject" wide //weight: 1
        $x_1_4 = {00 00 09 4c 00 6f 00 61 00 64 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "DisposeWinPanel" ascii //weight: 1
        $x_1_6 = "DrawWinPanel" ascii //weight: 1
        $x_1_7 = "WinPanelCreate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPM_2147817552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPM!MTB"
        threat_id = "2147817552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tuandoquoc77@gmail.com" wide //weight: 1
        $x_1_2 = "dotuan.plus@gmail.com" wide //weight: 1
        $x_1_3 = "Keylogger" wide //weight: 1
        $x_1_4 = "CheckHotKey" ascii //weight: 1
        $x_1_5 = "CallNextHookEx" ascii //weight: 1
        $x_1_6 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_7 = "HookKeyboard" ascii //weight: 1
        $x_1_8 = "set_IsBackground" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 8e 69 0a 03 04 17 58 06 5d 91 2a}  //weight: 1, accuracy: High
        $x_1_2 = {03 04 61 05 59 20 00 01 00 00 58 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 04 2b 1e 07 09 11 04 6f 67 00 00 0a 13 06 08 12 06 28 68 00 00 0a 6f 69 00 00 0a 11 04 17 58 13 04 11 04 07 6f 6a 00 00 0a 32 d8 09 17 58 0d 09 07 6f 6b 00 00 0a 32 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b}  //weight: 1, accuracy: High
        $x_1_2 = {13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 14 11 14 11 13 1f 16 5d 91 13 15 07 11 13 91 11 15 61 13 16 11 13 17 58 08 5d 13 17 07 11 17 91 13 18 11 16 11 18 59 13 19 20 ff 00 00 00 13 1a 11 19 20 00 01 00 00 58 11 1a 5f 13 1b 07 11 13 11 1b d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 91 11 07 61 13 08 11 05 17 58 08 5d 13 09 1f 3f 13 11 38 0d fa ff ff 07 11 09 91 13 0a 11 08 11 0a 59 13 0b 20 ff 00 00 00 13 0c 20 ab 00 00 00 13 11 38 ed f9 ff ff 11 0b 20 00 01 00 00 58 11 0c 5f 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 08 09 6e 08 8e 69 6a 5d d4 91 13 0b 11 04 11 0b 58 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 00 09 17 58 0d 09 20 ff 00 00 00 fe 03 16 fe 01 13 0c 11 0c 2d b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPY_2147818093_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPY!MTB"
        threat_id = "2147818093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger started" wide //weight: 1
        $x_1_2 = "keystrokes.txt" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "Hacked" wide //weight: 1
        $x_1_5 = "voiceStart" wide //weight: 1
        $x_1_6 = "screenshot" wide //weight: 1
        $x_1_7 = "IsKeyLocked" ascii //weight: 1
        $x_1_8 = "StartVoice" ascii //weight: 1
        $x_1_9 = "record" ascii //weight: 1
        $x_1_10 = "DownloadFile" ascii //weight: 1
        $x_1_11 = "Rat-Bot.exe" ascii //weight: 1
        $x_1_12 = "GetTempPath" ascii //weight: 1
        $x_1_13 = "CaptureScreen" ascii //weight: 1
        $x_1_14 = "IsKeyDown" ascii //weight: 1
        $x_1_15 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPZ_2147818094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPZ!MTB"
        threat_id = "2147818094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0yth/ZdiicEy7AxWuTYHUw==" wide //weight: 1
        $x_1_2 = "jjs2DL/ZNwm5veY8BpuqvAQqCv8zwVyBdIT+HiMsTs4=" wide //weight: 1
        $x_1_3 = "cdn.discordapp.com" wide //weight: 1
        $x_1_4 = "Uqnnjh.dat" wide //weight: 1
        $x_1_5 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RPZ_2147818094_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RPZ!MTB"
        threat_id = "2147818094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinKeyLogger" wide //weight: 1
        $x_1_2 = "Autostart Logging" wide //weight: 1
        $x_1_3 = "logdir" wide //weight: 1
        $x_1_4 = "WriteLog" ascii //weight: 1
        $x_1_5 = "Encoding" ascii //weight: 1
        $x_1_6 = "AsyncCallback" ascii //weight: 1
        $x_1_7 = "LibKeyHook" ascii //weight: 1
        $x_1_8 = "GetForegroundWindow" ascii //weight: 1
        $x_1_9 = "MouseEventArgs" ascii //weight: 1
        $x_1_10 = "FormClosingEventArgs" ascii //weight: 1
        $x_1_11 = "CancelEventArgs" ascii //weight: 1
        $x_1_12 = "KeyDownEventArgs" ascii //weight: 1
        $x_1_13 = "KeyUpEventArgs" ascii //weight: 1
        $x_1_14 = "KeyDownAndUpEventArgs" ascii //weight: 1
        $x_1_15 = "KeyDetector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NT_2147818331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NT!MTB"
        threat_id = "2147818331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$abc4ce3c-2c7b-42be-b3d6-2d01bcd3bf6f" ascii //weight: 1
        $x_1_2 = "FinalProject.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NHG_2147818586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NHG!MTB"
        threat_id = "2147818586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$c27b1d8c-e849-4b6f-a020-c5260f83b43e" ascii //weight: 1
        $x_1_2 = "MapEditor.Propertie" ascii //weight: 1
        $x_1_3 = "N5GH8GVY3S84858FG0G5HJ" ascii //weight: 1
        $x_1_4 = "System.Reflection.Assembly" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NVB_2147819711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NVB!MTB"
        threat_id = "2147819711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 04 17 da 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 07 11 04 07 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 da 13 05 08 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 11 04 17 d6 13 04 11 04 09 31 bc}  //weight: 1, accuracy: Low
        $x_1_2 = "Bunifu_TextBox" wide //weight: 1
        $x_1_3 = "Invisce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NVD_2147819985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NVD!MTB"
        threat_id = "2147819985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 17 58 7e ?? ?? ?? 04 5d 91 0a 16 0b 02 03 28 ?? ?? ?? 06 0c 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e ?? ?? ?? 04 5d 07 d2 9c 02 13 04 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {04 5d 91 0a 06 7e ?? ?? ?? 04 03 1f 16 5d 6f ?? ?? ?? 0a 61 0b 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NU_2147821132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NU!MTB"
        threat_id = "2147821132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 70 01 00 0b 2b 1d 00 06 07 23 33 33 33 33 33 e3 6f 40 28 ?? ?? ?? 0a 69 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NV_2147822308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NV!MTB"
        threat_id = "2147822308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 dd a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a4 00 00 00 4f 00 00 00 42 03 00 00 a0 07 00 00 13 04 00 00 40 01 00 00 56 00 00 00 1b 00 00 00 01 00 00 00 01 00 00 00 76 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = {57 5d a2 c9 09 0b 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 96 00 00 00 45 00 00 00 17 03 00 00 e0 03 00 00 13 04 00 00 2c 01 00 00 56 00 00 00 1a 00 00 00 01 00 00 00 69 00 00 00 02 00 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NL_2147822316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NL!MTB"
        threat_id = "2147822316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 df b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a3 00 00 00 3b 00 00 00 fd 00 00 00 cf 03 00 00 87 01 00 00 02 00 00 00 68 01 00 00 05 00 00 00 a2 00 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NP_2147823615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NP!MTB"
        threat_id = "2147823615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d7 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 6d 00 00 00 19 00 00 00 56 00 00 00 4a 01 00 00 34 00 00 00 01 00 00 00 bf 00 00 00 1f 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "SASSSSSSSSSSSSSSSSSSSSSS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NS_2147823653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NS!MTB"
        threat_id = "2147823653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 06 6f 1a 00 00 0a 08 07 6f 1b 00 00 0a 08 6f 1c 00 00 0a 0d 73 1d 00 00 0a 25 09 03 16 03 8e 69 6f 1e 00 00 0a 6f 1f 00 00 0a 13 04}  //weight: 2, accuracy: High
        $x_1_2 = {28 05 00 00 0a 03 6f 06 00 00 0a 0a 06 14 28 07 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NS_2147823653_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NS!MTB"
        threat_id = "2147823653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 00 00 34 01 00 00 1e 03 00 00 33 00 00 00 0d 00 00 00 b7 00 00 00 64 01 00 00 0d 00 00 00 10 00 00 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 a2 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9a 00 00 00 15 00 00 00 c4 00 00 00 5f 03 00 00 12}  //weight: 1, accuracy: High
        $x_1_3 = "BugTrackerFinalProject.Resources.resource" ascii //weight: 1
        $x_1_4 = {07 00 00 00 05 00 00 00 05 00 00 00 05 00 00 00 0f 00 00 00 02 00 00 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_5 = "FromBase64CharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NY_2147825864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NY!MTB"
        threat_id = "2147825864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 73 21 00 00 0a 0a 73 22 00 00 0a 0b 06 16 73 23 00 00 0a 73 24 00 00 0a 0c 08 07 6f 25 00 00 0a de 0a}  //weight: 1, accuracy: High
        $x_1_2 = "oneliners.exe" wide //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "CreateDelegate" ascii //weight: 1
        $x_1_5 = "DynamicInvoke" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NYA_2147825865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NYA!MTB"
        threat_id = "2147825865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 3f b6 1f 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 1c 01 00 00 81 00 00 00 79 01 00 00 25 03 00 00 e7 02 00 00 17 00 00 00 ad 02}  //weight: 1, accuracy: High
        $x_1_2 = {10 00 00 00 af 00 00 00 1c 00 00 00 b8 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 0b 00 00 00 0f 00 00 00 37 00 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABW_2147827399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABW!MTB"
        threat_id = "2147827399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 14 72 85 ?? ?? 70 6f 40 ?? ?? 0a 0b 72 87 ?? ?? 70 0c 06 28 23 ?? ?? 0a 28 21 ?? ?? 0a 00 08 28 23 ?? ?? 0a 28 21 ?? ?? 0a 00 07 72 b5 ?? ?? 70 6f 55 ?? ?? 0a 28 21 ?? ?? 0a 00 07 72 9d ?? ?? 70 6f 45 ?? ?? 0a 28 21 ?? ?? 0a 00 08 28 2f ?? ?? 0a 0d 09 28 21 ?? ?? 06 13 04 72 c5 ?? ?? 70 07 72 f3 ?? ?? 70 28 44 ?? ?? 0a 13 05 08 7b 00 02 6f ea ?? ?? 06 6f 06 ?? ?? 06 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "DateTime" ascii //weight: 1
        $x_1_3 = "get_ScriptTime" ascii //weight: 1
        $x_1_4 = "GetCsMetadataPath" ascii //weight: 1
        $x_1_5 = "GetDestinationFilePath" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "ICryptoTransform" ascii //weight: 1
        $x_1_8 = "GetDomain" ascii //weight: 1
        $x_1_9 = "WriteAllTextWithBackup" ascii //weight: 1
        $x_1_10 = "InvokeMember" ascii //weight: 1
        $x_1_11 = "RC2CryptoServiceProvider" ascii //weight: 1
        $x_1_12 = "CreateDecryptor" ascii //weight: 1
        $x_1_13 = "LogDirectories" ascii //weight: 1
        $x_1_14 = "ReadAllText" ascii //weight: 1
        $x_1_15 = "WriteAllText" ascii //weight: 1
        $x_1_16 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEB_2147828116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEB!MTB"
        threat_id = "2147828116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = "bin_Nnqyccju.jpg" wide //weight: 1
        $x_1_3 = "Hbwluazsi" wide //weight: 1
        $x_1_4 = "Lzcwozlgncvnrybvckjtt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEC_2147828118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEC!MTB"
        threat_id = "2147828118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 b8 00 00 0a 28 c9 00 00 0a 14 72 ?? 08 00 70 72 ?? 08 00 70 72 ?? 08 00 70 28 b8 00 00 0a 1b 8d 17 00 00 01 25}  //weight: 1, accuracy: Low
        $x_1_2 = "get_v4_460px_Know_if_Your_Girlfriend_Is" ascii //weight: 1
        $x_1_3 = "Buni555fu_Te5555xtB555ox" wide //weight: 1
        $x_1_4 = "System.C0nvert" wide //weight: 1
        $x_1_5 = "Inv0keMember" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NED_2147828119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NED!MTB"
        threat_id = "2147828119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Privax HMA VPN" ascii //weight: 1
        $x_1_2 = "b77a5c561934e089" ascii //weight: 1
        $x_1_3 = "pOMMQQQ" ascii //weight: 1
        $x_1_4 = "jDQdqq" ascii //weight: 1
        $x_1_5 = "E*++immerr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NE_2147828123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NE!MTB"
        threat_id = "2147828123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 07 28 54 00 00 0a 13 08 00 11 06 72 57 06 00 70 11 08 28 55 00 00 0a 13 06 00 12 07 28 56 00 00 0a 3a d9 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {00 11 03 6f 35 00 00 0a 11 00 16 11 00 8e 69 28 29 00 00 06 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEE_2147828310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEE!MTB"
        threat_id = "2147828310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 91 13 05 08 12 05 72 8a 02 00 70 28 16 00 00 0a 6f 17 00 00 0a 6f 18 00 00 0a 26 11 04 17 58 13 04 11 04 09 8e 69 32 d5}  //weight: 1, accuracy: High
        $x_1_2 = "fu03uegyXyGG6mU04/bS8EOnIpDto7MxZLnq4rhpoArj25iafV4HGOPQn" wide //weight: 1
        $x_1_3 = "sDTRwPLWdPxRSAcfMGXyQnWCSzCpJKHiYHZgNoTmAEZLkDjXrFMNFtQbBEJqYaGeKBLPaiBTNoTdFJKnYjXXG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEF_2147828318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEF!MTB"
        threat_id = "2147828318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$61EF826B-B598-43F7-970F-C1815D3E515A" ascii //weight: 1
        $x_1_2 = "=WLG2PHLR" ascii //weight: 1
        $x_1_3 = "FKSLcBPA=" ascii //weight: 1
        $x_1_4 = "RSAPSS" wide //weight: 1
        $x_1_5 = "C0GKSMKIPA7X8WL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABZ_2147828475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABZ!MTB"
        threat_id = "2147828475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {57 bf a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b8 00 00 00 44 00 00 00 1a 01 00 00 ce 02 00 00 18 02 00 00}  //weight: 6, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "FlushFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABN_2147828763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABN!MTB"
        threat_id = "2147828763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 17 a2 09 09 09 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 42 00 00 00 17 00 00 00 36 00 00 00 8e 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "getWebResponse" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "Jambo" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "Shitz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEG_2147828930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEG!MTB"
        threat_id = "2147828930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8f 07 00 00 01 25 47 7e 5d 00 00 04 19 11 0e 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 0e 58 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEH_2147829564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEH!MTB"
        threat_id = "2147829564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 06 07 6f 7e 00 00 0a 6f ?? 00 00 0a 00 07 16 6f ?? 00 00 0a 00 16 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEI_2147829567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEI!MTB"
        threat_id = "2147829567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 1f 0a 6f ?? 00 00 0a 13 04 07 06 11 04 93 6f ?? 00 00 0a 26 00 09 17 58 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABV_2147829604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABV!MTB"
        threat_id = "2147829604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b9 00 00 00 38 00 00 00 09 01 00 00 b7 02 00 00 db 01 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "VersioningHel.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABT_2147830422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABT!MTB"
        threat_id = "2147830422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 09 16 11 04 2b 15 08 09 16 09 8e 69 6f ?? ?? ?? 0a 25 13 04 16 30 02 2b 09 2b e4 6f ?? ?? ?? 0a 2b e4 07 6f ?? ?? ?? 0a 13 05 de 17}  //weight: 4, accuracy: Low
        $x_4_2 = {72 33 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a}  //weight: 4, accuracy: Low
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABT_2147830422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABT!MTB"
        threat_id = "2147830422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 28 70 00 00 06 26 7e 6b 00 00 04 18 6f bf 00 00 0a 00 02 28 72 00 00 06 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_2_2 = {7e 6b 00 00 04 6f bc 00 00 0a 02 16 02 8e 69 6f bd 00 00 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "Helper_Classes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABAD_2147833107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABAD!MTB"
        threat_id = "2147833107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d a9 7e ?? ?? ?? 04 28 ?? ?? ?? 06 80 ?? ?? ?? 04 2a}  //weight: 6, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Pink" wide //weight: 1
        $x_1_4 = "Poker.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABBI_2147834310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABBI!MTB"
        threat_id = "2147834310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 1c 00 00 04 6f 3a 00 00 0a 02 16 02 8e 69 6f 3b 00 00 0a 0a 2b 00 06 2a}  //weight: 3, accuracy: High
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Shtoockie.Properties.Resources" wide //weight: 1
        $x_1_5 = "Helper_Classes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NZB_2147836037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NZB!MTB"
        threat_id = "2147836037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 52 30 35 33 36 00 73 65 74 5f 52 30 35 33 36 00 52 30 35 33 35 00 63 63 63 00 52 30 35 33 37 00 42 69 74 6d 61 70 00 52 30 35 33 38}  //weight: 1, accuracy: High
        $x_1_2 = "R0539" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RS_2147836246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RS!MTB"
        threat_id = "2147836246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 07 11 09 9a 1f 10 28 68 00 00 0a 6f 69 00 00 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RS_2147836246_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RS!MTB"
        threat_id = "2147836246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 4b 00 00 0a 1f 10 28 4c 00 00 0a 9c 1e 13 09 38 f5 f7 ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {11 06 07 8e 69 fe 04 13 07 11 07 2d 15 11 0a 20 a9 00 00 00 94 20 0c 70 00 00 59 13 09 38 c3 f7 ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABEQ_2147836382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABEQ!MTB"
        threat_id = "2147836382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_A_2147837518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.A!MTB"
        threat_id = "2147837518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PP000000000000001" ascii //weight: 2
        $x_2_2 = "WindowsApp1" ascii //weight: 2
        $x_2_3 = "K000001" ascii //weight: 2
        $x_1_4 = "GetMethod" wide //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_A_2147837518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.A!MTB"
        threat_id = "2147837518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 9e 00 00 00 2b 00 00 00 05 01 00 00 45 01 00 00 64 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "9c6251dc-6a93-48bb-bccf-e187420058ca" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "get_Length" ascii //weight: 1
        $x_1_8 = "GetType" ascii //weight: 1
        $x_1_9 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_B_2147837525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.B!MTB"
        threat_id = "2147837525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d b2 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 65 01 00 0a 1f 10 28 66 01 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "a4c9954c-97d9-4f17-a226-15ea8ddd9331" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_B_2147837525_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.B!MTB"
        threat_id = "2147837525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lipps.Resources.resources" ascii //weight: 2
        $x_2_2 = "00'00'" wide //weight: 2
        $x_2_3 = "Control_Run" wide //weight: 2
        $x_1_4 = "GetMethod" wide //weight: 1
        $x_2_5 = "<93<C2<00#<C0#<0D" wide //weight: 2
        $x_1_6 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_C_2147837529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.C!MTB"
        threat_id = "2147837529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f ?? 9d 6f ?? 01 00 0a 06 00 00 00 06 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {08 11 07 72 ?? ?? ?? 70 28 ?? ?? 00 0a 72 ?? ?? ?? 70 20 00 01 00 00 14 14 18 8d ?? 00 00 01 25 16 07 11 07 9a a2 25 17 1f 10 8c ?? 00 00 01 a2 6f ?? ?? 00 0a a5 ?? 00 00 01 9c 11 07 17 58}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 25 16 1f ?? 9d 6f ?? 01 00 0a 06 00 00 00 04 17 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABFP_2147838438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABFP!MTB"
        threat_id = "2147838438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 07 17 58 0b 07 20 ?? ?? ?? 00 fe 04 2d de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DAA_2147839167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DAA!MTB"
        threat_id = "2147839167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 b5 02 3c 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 65 00 00 00 4e 00 00 00 88 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Target Realty" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "Unwrap" ascii //weight: 1
        $x_10_7 = {57 97 02 2a 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 35 00 00 00 1e 00 00 00 27 00 00 00}  //weight: 10, accuracy: High
        $x_1_8 = "Infinity" ascii //weight: 1
        $x_1_9 = "GetExtension" ascii //weight: 1
        $x_1_10 = "GetTempPath" ascii //weight: 1
        $x_1_11 = "get_Assembly" ascii //weight: 1
        $x_1_12 = "Rollback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_D_2147839641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.D!MTB"
        threat_id = "2147839641"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 61 28}  //weight: 2, accuracy: High
        $x_2_2 = {8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MB_2147839831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MB!MTB"
        threat_id = "2147839831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 5e 00 00 00 0c 00 00 00 6c 00 00 00 57 00 00 00 53}  //weight: 5, accuracy: High
        $x_2_2 = "FortudeSecond.Properties" ascii //weight: 2
        $x_2_3 = "Jambo" ascii //weight: 2
        $x_2_4 = "txtQty_KeyPress" ascii //weight: 2
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MC_2147839919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MC!MTB"
        threat_id = "2147839919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 69 8d 66 00 00 01 25 17 73 2c 00 00 0a 13 04 06 6f ?? ?? ?? 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09}  //weight: 5, accuracy: Low
        $x_5_2 = "BouncingBalls.Properties" ascii //weight: 5
        $x_5_3 = {57 ff a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 7e 00 00 00 2b 00 00 00 cc 00 00 00 c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DAB_2147840007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DAB!MTB"
        threat_id = "2147840007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {57 1f a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 00 00 00 09 00 00 00 15 00 00 00 35}  //weight: 20, accuracy: High
        $x_1_2 = "CaloriesCalculator" ascii //weight: 1
        $x_1_3 = "Jambo" ascii //weight: 1
        $x_1_4 = "Jogging" ascii //weight: 1
        $x_1_5 = "Swimming" ascii //weight: 1
        $x_1_6 = "Pumprize" ascii //weight: 1
        $x_20_7 = {57 1f b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 95 00 00 00 42 00 00 00 40 00 00 00 08}  //weight: 20, accuracy: High
        $x_1_8 = "TrollRAT" ascii //weight: 1
        $x_1_9 = "get_Payload" ascii //weight: 1
        $x_1_10 = "GZipStream" ascii //weight: 1
        $x_1_11 = "CopyFromScreen" ascii //weight: 1
        $x_1_12 = "injection" ascii //weight: 1
        $x_20_13 = {57 b5 02 1c 09 0e 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 27 00 00 00 18 00 00 00 2b 00 00 00 56}  //weight: 20, accuracy: High
        $x_1_14 = "AES_Decrypt" ascii //weight: 1
        $x_1_15 = "BlockCopy" ascii //weight: 1
        $x_1_16 = "LowNetwork" ascii //weight: 1
        $x_1_17 = "startupInfo" ascii //weight: 1
        $x_1_18 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_MD_2147840366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MD!MTB"
        threat_id = "2147840366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb 69 ff 26 19 ff a2 69 bb}  //weight: 3, accuracy: High
        $x_3_2 = {1f 63 20 02 1f 63 20 02 32 7d 36 08 14 90 19 73 19 94 1e bf 20 98 25 e6 20 98 25 f9 21 9a 27 fa 1e 98 24 fe 1e 98 23 ff 1f}  //weight: 3, accuracy: High
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MJ_2147840570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MJ!MTB"
        threat_id = "2147840570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 6f 0c 00 00 0a 13 05 11 05 72 e6 2a 0e 70 72 f8 2a 0e 70 28 01 00 00 06 13 06 18 8d 0b 00 00 01 13 07 11 07 16 72 32 2b 0e 70 a2 11 07 17 11 06 28 01 00 00 0a a2 11 07 13 08}  //weight: 10, accuracy: High
        $x_2_2 = "Gotic2.Gotic2" wide //weight: 2
        $x_2_3 = "TTRDZBWIimjJZrG" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ML_2147840600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ML!MTB"
        threat_id = "2147840600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 09 07 16 07 8e 69 6f ?? ?? ?? 0a 13 04 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 05 dd 0d 00 00 00 26 7e ?? 00 00 0a 13 05 dd}  //weight: 10, accuracy: Low
        $x_2_2 = "TTRDZBWIimjJZrG" wide //weight: 2
        $x_2_3 = "Gotic2.Gotic2" wide //weight: 2
        $x_2_4 = "Manager_Jit_BoolToInt.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MP_2147840673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MP!MTB"
        threat_id = "2147840673"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 08 73 3e 00 00 0a 13 04 11 04 09 06 07 6f ?? ?? ?? 0a 16 73 40 00 00 0a 13 05 11 05 73 41 00 00 0a 13 06 11 06 6f ?? ?? ?? 0a 2a 11 07 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "Gotic2.Gotic2" wide //weight: 2
        $x_2_3 = "TTRDZBWIimjJZrG" wide //weight: 2
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MF_2147840706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MF!MTB"
        threat_id = "2147840706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 9d a2 29 09 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 45 00 00 00 18 00 00 00 50 00 00 00 69 00 00 00 ac}  //weight: 5, accuracy: High
        $x_2_2 = "Jambo" ascii //weight: 2
        $x_2_3 = "SoftRenderer.Properties" ascii //weight: 2
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "InitializeComponent" ascii //weight: 1
        $x_1_6 = "e9f18a30-57c0-43f0-91b6-0796b6810190" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MH_2147840707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MH!MTB"
        threat_id = "2147840707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 11 05 72 af a0 18 70 72 c1 a0 18 70 28 ?? ?? ?? 06 13 06 18 8d 05 00 00 01 13 07 11 07 16 72 d3 a0 18 70 a2 11 07 17 11 06 28 ?? ?? ?? 0a a2 11 07 13 08 08}  //weight: 10, accuracy: Low
        $x_10_2 = {13 05 11 05 72 ef f5 18 70 72 01 f6 18 70 28 ?? ?? ?? 06 13 06 18 8d 05 00 00 01 13 07 11 07 16 72 13 f6 18 70 a2 11 07 17 11 06 28 ?? ?? ?? 0a a2 11 07 13 08 08}  //weight: 10, accuracy: Low
        $x_2_3 = "Gotic2.Gotic2" wide //weight: 2
        $x_2_4 = "TTRDZBWIimjJZrG" wide //weight: 2
        $x_1_5 = "FlushFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_MQ_2147840841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MQ!MTB"
        threat_id = "2147840841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0d 09 07 16 07 8e 69 6f 1d 00 00 0a 13 04 28 16 00 00 0a 11 04 6f 1e 00 00 0a 13 05 dd 0d 00 00 00 26 7e 0c 00 00 0a 13 05 dd}  //weight: 10, accuracy: High
        $x_2_2 = "TTRDZBWIimjJZrG" wide //weight: 2
        $x_2_3 = "Gotic2.Gotic2" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MG_2147840852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MG!MTB"
        threat_id = "2147840852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 08 12 08 28 ?? ?? ?? 0a 26 11 06 72 8d a4 10 70 72 9f a4 10 70 28 ?? ?? ?? 06 13 09 11 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 b1 a4 10 70 6f 0e 00 00 0a 72 cd a4 10 70 20 00 01 00 00 14 14 11 05}  //weight: 5, accuracy: Low
        $x_2_2 = "NFSLocale_MainForm" ascii //weight: 2
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MI_2147840853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MI!MTB"
        threat_id = "2147840853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df 09 13 05 de 42}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MO_2147840855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MO!MTB"
        threat_id = "2147840855"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 17 a2 1f 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 79 00 00 00 0a 00 00 00 36 00 00 00 3e 00 00 00 31}  //weight: 5, accuracy: High
        $x_2_2 = "testlogin.Properties" ascii //weight: 2
        $x_2_3 = "e78867da-c05b-4467-9964-cbc719fe6dfc" ascii //weight: 2
        $x_2_4 = "Jelesis" ascii //weight: 2
        $x_2_5 = "select count(*) from userpwd where username=" wide //weight: 2
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MR_2147840990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MR!MTB"
        threat_id = "2147840990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 06 07 11 06 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dd}  //weight: 5, accuracy: Low
        $x_1_2 = "2dd06729-4684-441e-a700-9cbbcfff7ed9" ascii //weight: 1
        $x_1_3 = "Run_Click" ascii //weight: 1
        $x_1_4 = "TryaAgain.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPA_2147841203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPA!MTB"
        threat_id = "2147841203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 07 8e 69 5d 02 07 11 04 28 ?? ?? ?? 06 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAS_2147841204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAS!MTB"
        threat_id = "2147841204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {12 01 28 11 00 00 06 26 00 07 06 59 20 e8 03 00 00 6a 5a 7e 17 00 00 04 5b 6c 02 6c fe 04 0c 08 2d dd}  //weight: 3, accuracy: High
        $x_1_2 = "hkyxDpEhpQxOiEshQCrDp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MS_2147841405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MS!MTB"
        threat_id = "2147841405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 0c 11 0c 72 46 bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 4e bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 56 bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 5e bd 02 70 28 02 00 00 0a 13 0c 11 0c 72 66 bd 02 70 28 02 00 00 0a 13 0c}  //weight: 5, accuracy: High
        $x_3_2 = "ErbnKhOBiWTSRKE" wide //weight: 3
        $x_3_3 = "hWQHlSOxHQKaNDv" wide //weight: 3
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_NEAB_2147841892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.NEAB!MTB"
        threat_id = "2147841892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a2 14 14 14 28 ?? 00 00 0a 14 72 ?? 46 02 70 18 8d ?? 00 00 01 25 16 72 ?? 46 02 70 a2 25 17 72 ?? 46 02 70 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "get_Naked_Beauty" ascii //weight: 2
        $x_2_3 = "Nude_Photos_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ME_2147842168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ME!MTB"
        threat_id = "2147842168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YFGGCVyufgtwfyuTGFWTVFAUYVF.exe" ascii //weight: 1
        $x_1_2 = "Win32_OperatingSystem" wide //weight: 1
        $x_1_3 = "$%TelegramDv$" wide //weight: 1
        $x_1_4 = "BsrOkyiChvpfhAkipZAxnnChkM" wide //weight: 1
        $x_1_5 = "LOCKDOWN2000" wide //weight: 1
        $x_1_6 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_7 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_8 = " | Snake Tracker" wide //weight: 1
        $x_1_9 = "/sendDocument?chat_id=" wide //weight: 1
        $x_1_10 = "\\SnakeKeylogger" wide //weight: 1
        $x_1_11 = "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPQS_2147842179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPQS!MTB"
        threat_id = "2147842179"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 6f 1b 00 00 0a 07 9a 6f 1c 00 00 0a 14 14 6f 1d 00 00 0a 2c 02 de}  //weight: 3, accuracy: High
        $x_1_2 = {00 28 12 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAL_2147842180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAL!MTB"
        threat_id = "2147842180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SunkBoatThree" ascii //weight: 1
        $x_1_2 = "SunkBoatTwo" ascii //weight: 1
        $x_1_3 = "SunkBoatOne" ascii //weight: 1
        $x_1_4 = "SunkChecker" ascii //weight: 1
        $x_1_5 = "DIKJUSHIJUWDOSHNIOUDWHDIUWEHD" wide //weight: 1
        $x_1_6 = "FEWQFWQFQWRQERQW" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRJ_2147842635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRJ!MTB"
        threat_id = "2147842635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 07 11 04 9a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 2a 11 2a 3a 8b fd ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "WFCubeAttack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRY_2147842969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRY!MTB"
        threat_id = "2147842969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1f 0d 02 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 16 28 ?? ?? ?? 06 0c de 20 07 14 fe 01 0d 09 2d 07 07 6f ?? ?? ?? 0a 00 dc}  //weight: 3, accuracy: Low
        $x_1_2 = "Windows_Local_Host_Prozess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRU_2147842970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRU!MTB"
        threat_id = "2147842970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a 1f 10 28 8c 00 00 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc}  //weight: 4, accuracy: High
        $x_1_2 = "wallsSlippedThrough" ascii //weight: 1
        $x_1_3 = "resetWonCardsDeckk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRP_2147843101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRP!MTB"
        threat_id = "2147843101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 7b 09 00 00 04 08 03 58 09 04 58 28 ?? ?? ?? 0a 1f 23 fe 01 13 05 11 05 2c 04 06 17 58 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "GAdminLib.ResourceDA" ascii //weight: 1
        $x_1_3 = "GTA_PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPD_2147843103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPD!MTB"
        threat_id = "2147843103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 20 00 80 01 00 8d 71 00 00 01 0b 06 72 d5 05 00 70 6f ?? ?? ?? 0a 74 08 00 00 1b 16 07 16 20 00 c0 00 00 28 ?? ?? ?? 0a 00 06 72 db 05 00 70 6f ?? ?? ?? 0a 74 08 00 00 1b 16}  //weight: 3, accuracy: Low
        $x_1_2 = "SixXFour" ascii //weight: 1
        $x_1_3 = "runUserTurn" ascii //weight: 1
        $x_1_4 = "runTurnes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_2147843131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MT!MTB"
        threat_id = "2147843131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 07 11 07 72 cf d5 09 70 6f ?? ?? ?? 0a 13 08 18 8d 03 00 00 01 13 09 11 09 16 72 0f d6 09 70 a2 11 09 17 09 a2 11 09 13 0a 11 08 72 83 d6 09 70 20 00 01 00 00 14 14 11 0a 6f ?? ?? ?? 0a 26 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPCP_2147843137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPCP!MTB"
        threat_id = "2147843137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DogToWin" ascii //weight: 1
        $x_1_2 = "Kruskal_64" ascii //weight: 1
        $x_1_3 = "Delete_Arco_64" ascii //weight: 1
        $x_1_4 = "Recorrido_Profunidad_64" ascii //weight: 1
        $x_1_5 = "aDayAtTheRaces" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_E_2147843247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.E!MTB"
        threat_id = "2147843247"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\My Works\\Visual Studio\\NDRWinFormGames\\Platformer\\Resources\\Environments\\Grass.png" wide //weight: 2
        $x_2_2 = "Ground.png" wide //weight: 2
        $x_1_3 = "GetExportedTypes" ascii //weight: 1
        $x_1_4 = "GetMethods" ascii //weight: 1
        $x_2_5 = "Skocko.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MU_2147843326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MU!MTB"
        threat_id = "2147843326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 16 6a 16 6f ?? ?? ?? 0a 26 08 28 ?? ?? ?? 0a 13 07 11 07 72 8b d5 09 70 6f ?? ?? ?? 0a 13 08 18 8d 06 00 00 01 13 09 11 09 16 72 cb d5 09 70 a2 11 09 17 11 05 a2 11 09 13 0a 11 08 72 3f d6 09 70 20 00 01 00 00 14 14 11 0a 6f ?? ?? ?? 0a 26 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPDS_2147843340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPDS!MTB"
        threat_id = "2147843340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 07 06 08 8f 73 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df}  //weight: 5, accuracy: Low
        $x_1_2 = "get_Marliece_Andrada" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MV_2147843432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MV!MTB"
        threat_id = "2147843432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 08 8f 6f 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df 07 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "05d594c5-2fad-4f7a-84e1-a0acfd767f06" ascii //weight: 2
        $x_2_3 = "Conway_s_Game.Properties" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_F_2147843843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.F!MTB"
        threat_id = "2147843843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 4a 1a 28 ?? 00 00 0a 0c 00 28 ?? 00 00 0a 28 ?? 00 00 0a 16 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPX_2147843950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPX!MTB"
        threat_id = "2147843950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 08 8d 54 00 00 01 0d 16 13 05 2b 71 00 07 19 11 05 5a 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06}  //weight: 2, accuracy: Low
        $x_1_2 = "get_Marliece_Andrada__40" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_G_2147843976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.G!MTB"
        threat_id = "2147843976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 06 28 36 00 00 06 26 00 08 18 d6 0c 08 07 fe 02 16 fe 01}  //weight: 2, accuracy: High
        $x_2_2 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPY_2147844278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPY!MTB"
        threat_id = "2147844278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 09 06 09 9a 1f 10 28 44 00 00 0a 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 3, accuracy: High
        $x_1_2 = "VitaminAper100" ascii //weight: 1
        $x_1_3 = "squeezableFruit_btn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MW_2147844367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MW!MTB"
        threat_id = "2147844367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 17 8c ?? 00 00 01 a2 25 17 18 8c ?? 00 00 01 a2 25 18 19 8c ?? 00 00 01 a2 25 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a a2 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRN_2147845312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRN!MTB"
        threat_id = "2147845312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 73 0e 00 00 0a 0b 07 20 80 00 00 00 6f ?? ?? ?? 0a 07 20 00 01 00 00 6f ?? ?? ?? 0a 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 28 ?? ?? ?? 0a 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 07 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08 06 16 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "maesMain.CreateDecryptor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MBDT_2147845539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MBDT!MTB"
        threat_id = "2147845539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 07 18 6f ?? 00 00 0a 20 03 02 00 00 28 ?? 00 00 0a 13 09 11 06 11 09 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 07 18 58 13 07 00 11 07 11 05 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAK_2147845599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAK!MTB"
        threat_id = "2147845599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CevrimiciIkiKisinin" wide //weight: 1
        $x_1_2 = "ALANLARI DOLDURUNUZ!!!!" wide //weight: 1
        $x_1_3 = "CevrimiciIkiKisinin.RE" wide //weight: 1
        $x_1_4 = "CevrimiciIkiKisinin.Properties.Resources" wide //weight: 1
        $x_1_5 = "MESAJLAR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAF_2147845657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAF!MTB"
        threat_id = "2147845657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frm_HsvColorpicker_Load" ascii //weight: 1
        $x_1_2 = "NicoPizzeria.Extensions" ascii //weight: 1
        $x_1_3 = "NicoPizzeria.Helpers" ascii //weight: 1
        $x_1_4 = "frm_HsvColorpicker" ascii //weight: 1
        $x_1_5 = "get_Marliece_45_Andrada" ascii //weight: 1
        $x_1_6 = "get_Marliece_Andrada" ascii //weight: 1
        $x_1_7 = "NicoPizzeria" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRF_2147845661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRF!MTB"
        threat_id = "2147845661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {00 06 03 07 8f 31 00 00 01 72 1d 01 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 1c fe 04 0c 08 2c 0e 00 06 72 51 11 00 70 28 ?? ?? ?? 0a 0a 00 00 07 17 58 0b 07 1c fe 04 0d 09 2d c4}  //weight: 4, accuracy: Low
        $x_1_2 = "IEEE_8025_TokenRing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABQS_2147845860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABQS!MTB"
        threat_id = "2147845860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 10 2b 15 2b 16 2b 1b 2b 1c 2b 21 2b 26 2b 2b de 2f 28 ?? ?? ?? 06 2b e9 0a 2b e8 28 ?? ?? ?? 0a 2b e3 06 2b e2 6f ?? ?? ?? 0a 2b dd 28 ?? ?? ?? 0a 2b d8 28 ?? ?? ?? 06 2b d3 0b 2b d2 26 de b9}  //weight: 3, accuracy: Low
        $x_3_2 = {07 91 9c 18 2c ed 19 2c 0f 02 07 08 9c 1c 2c e1 06 17 58 0a 07 17 59 0b 06 07 32 d7 02 2a}  //weight: 3, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABQN_2147845883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABQN!MTB"
        threat_id = "2147845883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 61 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd ?? ?? ?? 00 26 dd ?? ?? ?? ff 07 2a}  //weight: 3, accuracy: Low
        $x_2_2 = "107.172.4.169/09/Datiycvj.bmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABRJ_2147845887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABRJ!MTB"
        threat_id = "2147845887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 72 df 06 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 e5 06 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 eb 06 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 f1 06 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABSI_2147845965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABSI!MTB"
        threat_id = "2147845965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 00 5a 00 2e 00 47 00 65 00 6e 00 65 00 74 00 69 00 63 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {74 00 72 00 61 00 65 00 6b 00 74 00 6f 00 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABSM_2147845966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABSM!MTB"
        threat_id = "2147845966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 19 11 14 5a 6f ?? 00 00 0a 13 15 11 15 1f 39 fe 02 13 17 11 17 2c 0d 11 15 1f 41 59 1f 0a 58 d1 13 15 2b 08 11 15 1f 30 59 d1 13 15 06 19 11 14 5a 17 58 6f ?? 00 00 0a 13 16 11 16 1f 39 fe 02 13 18 11 18 2c 0d 11 16 1f 41 59 1f 0a 58 d1 13 16 2b 08 11 16 1f 30 59 d1 13 16 08 11 14 1f 10 11 15 5a 11 16 58 d2 9c 00 11 14 17 58 13 14 11 14 07 fe 04 13 19 11 19 2d 84}  //weight: 5, accuracy: Low
        $x_1_2 = "BoardGameProject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRE_2147846051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRE!MTB"
        threat_id = "2147846051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 15 00 00 0a 0a 02 73 16 00 00 0a 0b 06 07 6f ?? ?? ?? 0a 0c de 0d 06 2c 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABUX_2147846403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABUX!MTB"
        threat_id = "2147846403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0d 2b 29 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 17 8d ?? 00 00 01 25 16 11 05 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d c8}  //weight: 4, accuracy: Low
        $x_1_2 = "quanlycuahang.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPG_2147846537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPG!MTB"
        threat_id = "2147846537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 05 08 11 05 6f ?? ?? ?? 0a 00 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAM_2147846662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAM!MTB"
        threat_id = "2147846662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 05 08 17 8d ?? ?? ?? 01 25 16 11 05 9c 6f ?? ?? ?? 0a 00 09 18 58 0d 00 09 07 6f ?? ?? ?? 0a fe 04 13 06 11 06 2d c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPL_2147846790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPL!MTB"
        threat_id = "2147846790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ezlenkoka" ascii //weight: 1
        $x_1_2 = "FacebookUserPostKeyPhras" ascii //weight: 1
        $x_1_3 = "FacebookPersonalityInsightsPersonality" ascii //weight: 1
        $x_1_4 = "MoodDetector.DataAccess.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MBCY_2147846884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MBCY!MTB"
        threat_id = "2147846884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 13 12 11 11 13 13 12 0f 28 ?? 00 00 0a 11 12 28 ?? 00 00 06 16 1e 6f ?? 00 00 0a 13 14 11 14 11 13 73 ?? 00 00 06 13 15 06 11 0f 11 15 6f ?? 00 00 0a 00 00 11 0e 17 58 13 0e 11 0e 11 09 fe 04 13 16 11 16 2d 84}  //weight: 1, accuracy: Low
        $x_1_2 = "91dcdafa374c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PSP_2147846897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PSP!MTB"
        threat_id = "2147846897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 11 0c 09 59 28 ?? ?? ?? 0a 13 0d 11 0c 09 58 17 58 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0e 11 0d 13 0f 2b 42 00 07 11 0f 91 13 10 11 10 2c 02}  //weight: 1, accuracy: Low
        $x_1_2 = "ZindgeSaxte" ascii //weight: 1
        $x_1_3 = "Ezlenkoka" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPO_2147847385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPO!MTB"
        threat_id = "2147847385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 06 09 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 09 8e 69 fe 04 13 07 11 07 2d dd}  //weight: 1, accuracy: Low
        $x_1_2 = "HoVuQuocTrung" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPM_2147847459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPM!MTB"
        threat_id = "2147847459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 16 06 8e 69 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 15 05 00 70 6f ?? ?? ?? 0a 0b 02 07 16 07 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "LakkaPlaylistTool.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABXP_2147847630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABXP!MTB"
        threat_id = "2147847630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 3d 16 0b 2b 25 11 06 06 07 6f ?? 00 00 0a 13 1e 12 1e 28 ?? 00 00 0a 13 17 11 0c 11 07 11 17 9c 11 07 17 58 13 07 07 17 58 0b 07 11 06 6f ?? 00 00 0a fe 04 13 18 11 18 2d cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPCS_2147848103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPCS!MTB"
        threat_id = "2147848103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 08 73 5b 00 00 0a 13 07 06 11 07 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7d 33 00 00 04 16 06 7b 33 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e 35 00 00 04 25 2d 17}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXL_2147848126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXL!MTB"
        threat_id = "2147848126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 09 5d 13 09 11 05 09 5b 13 0a 08 11 09 11 0a 6f ?? ?? ?? 0a 13 0b 07 11 06 12 0b 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9}  //weight: 1, accuracy: Low
        $x_1_2 = "Puntos_de_la_pieza" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABYC_2147848239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABYC!MTB"
        threat_id = "2147848239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 19 00 7e ?? 00 00 04 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "WordListAnalyser2.Properties.Resources" wide //weight: 1
        $x_1_3 = "SpaceTeam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABYI_2147848241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABYI!MTB"
        threat_id = "2147848241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 19 00 7e ?? 00 00 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "SpaceTeam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABYK_2147848455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABYK!MTB"
        threat_id = "2147848455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 27 00 00 0a 0a 02 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 38 ?? 00 00 00 07 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2d ea dd ?? 00 00 00 07 39 ?? 00 00 00 07 6f ?? 00 00 0a dc 06 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ABYO_2147848553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ABYO!MTB"
        threat_id = "2147848553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 03 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 19 00 7e ?? 00 00 04 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "SpaceTeam" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AABU_2147849165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AABU!MTB"
        threat_id = "2147849165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 b3 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 36 11 05 11 08 9a 72 b7 02 00 70 28 ?? 00 00 0a 2c 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 1a 11 05 11 08 9a 72 bb 02 00 70 28 ?? 00 00 0a 2c 09 12 0b 28 ?? 00 00 0a 13 0c 07 11 0c 6f ?? 00 00 0a 11 0a 17 58 13 0a 11 0a 09 32 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAX_2147850043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAX!MTB"
        threat_id = "2147850043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/6xTrJ5wusITyu1Aj0dx7FCdXZASmLZVhm2ZAII8rs4=" wide //weight: 1
        $x_1_2 = "AkpB9/oRevHUxXqmd0RltQ==" wide //weight: 1
        $x_1_3 = "IblpKzP/zq8ziiMGKDhlqw==" wide //weight: 1
        $x_1_4 = "Luv3CAkRF1eo3OWmM0SQ7g==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAT_2147850793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAT!MTB"
        threat_id = "2147850793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 9a 0d 00 02 09 02 7b ?? ?? ?? 04 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 11 04 16 fe 01 13 05 11 05 2c 06 11 04 13 06 2b 10 00 08 17 58 0c 08 07 8e 69 32 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SDP_2147850796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SDP!MTB"
        threat_id = "2147850796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 18 6f ?? 00 00 0a 13 07 08 11 06 18 5b 11 07 1f 10 28 ?? 00 00 0a 9c 00 11 06 18 58 13 06 11 06 07 6f ?? 00 00 0a fe 04 13 08 11 08 2d ce}  //weight: 1, accuracy: Low
        $x_1_2 = "QuanLyQuanTS.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SXD_2147850798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SXD!MTB"
        threat_id = "2147850798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 10 00 00 0a 13 07 11 05 18 5f 2c 03 16 2b 03 17 2b 00 3a 9d 00 00 00 06 6f ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 16 73 12 00 00 0a 13 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SXC_2147851312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SXC!MTB"
        threat_id = "2147851312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 09 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2c cd}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SK_2147851334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SK!MTB"
        threat_id = "2147851334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 07 11 09 58 17 58 17 59 11 08 11 0a 58 17 58 17 59 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 0c 09 08 11 0c 9c 08 17 58 0c 11 0a 17 58 13 0a 00 11 0a 17 fe 04 13 0d 11 0d 2d c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPWR_2147889139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPWR!MTB"
        threat_id = "2147889139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 1e 11 17 6f ?? ?? ?? 0a 13 3e 11 0d 11 3e 11 22 59 61 13 0d 11 22 19 11 0d 58 1e 63 59 13 22 11 17 6f ?? ?? ?? 06 2d d9 de 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRT_2147890121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRT!MTB"
        threat_id = "2147890121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 07 a3 01 00 00 01 0c 73 ?? ?? ?? 0a 0d 09 72 01 00 00 70 28 ?? ?? ?? 0a 72 33 00 00 70 28 ?? ?? ?? 0a 6f 04 00 00 0a 13 04 14 13 05 38 31 00 00 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPUT_2147890123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPUT!MTB"
        threat_id = "2147890123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 74 04 00 70 72 78 04 00 70 6f ?? ?? ?? 0a 0d 07 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? 00 13 05 17 8d ?? ?? ?? 01 25 16 7e 1f 00 00 04 a2 13 06 72 7a 04 00 70 72 47 06 00 70 72 78 04 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 11 07}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAD_2147891382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAD!MTB"
        threat_id = "2147891382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 20 c4 28 00 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 20 ab 28 00 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 02 28 ?? ?? ?? 06 75 03 00 00 1b 73 ?? ?? ?? 0a 0d 09 07 16 73 0f 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AMAA_2147891900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AMAA!MTB"
        threat_id = "2147891900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 20 00 01 00 00 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AMAA_2147891900_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AMAA!MTB"
        threat_id = "2147891900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 02 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 13 05 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "GetAsync" ascii //weight: 1
        $x_1_5 = "HttpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAP_2147891967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAP!MTB"
        threat_id = "2147891967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 40 f4 c1 53 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 20 3f f4 c1 53 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 73 f6 00 00 0a 0b 14 fe 06 2a 05 00 06 73 2a 03 00 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 75 8b 00 00 1b 73 03 02 00 0a 0c 08 11 04 16 73 2b 03 00 0a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAQ_2147892357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAQ!MTB"
        threat_id = "2147892357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 11 04 16 73 55 02 00 0a 0d 09 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 05 de 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAI_2147892973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAI!MTB"
        threat_id = "2147892973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 09 07 16 73 ?? ?? ?? 0a 13 04 11 04 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 05 de 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXY_2147893835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXY!MTB"
        threat_id = "2147893835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0b 72 3f 0c 00 70 0c 08 72 8f 0c 00 70 72 67 0a 00 70 6f ?? ?? ?? 0a 0d 07 28 ?? ?? ?? 0a 13 04 20 00 01 00 00 13 05 17 8d 12 00 00 01 25 16 7e 5c 00 00 04 a2 13 06 72 93 0c 00 70 72 60 0e 00 70 72 67 0a 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 11 07}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPQE_2147893890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPQE!MTB"
        threat_id = "2147893890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 28 ?? ?? ?? 06 07 09 17 58}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPQM_2147894266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPQM!MTB"
        threat_id = "2147894266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 01 00 00 04 6f ?? ?? ?? 0a 05 03 02 8e 69 6f ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 0a 00 06 0b 2b 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_CCDV_2147896157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.CCDV!MTB"
        threat_id = "2147896157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LThyvwDJBksDyAJZUMTkCxA" ascii //weight: 1
        $x_1_2 = "kiUhOQUQCsCfyQQnvvpTsnT" ascii //weight: 1
        $x_1_3 = "fsBZQhCisirEBOOUfyDCTsT" ascii //weight: 1
        $x_1_4 = "xpCBkyiUvBEDLwyxLQLpfLi" ascii //weight: 1
        $x_1_5 = "LQvwkMpyUJMpULATAxCZv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_GKP_2147896641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.GKP!MTB"
        threat_id = "2147896641"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ca31ba91-6e0e-4cf7-a8e0-6192f5868ee5" ascii //weight: 1
        $x_1_2 = "DACls.exe" ascii //weight: 1
        $x_1_3 = "set_UseSystemPasswordChar" ascii //weight: 1
        $x_1_4 = "QuanLyDangKyInternetConnectionString" ascii //weight: 1
        $x_1_5 = "CreateDelegate" ascii //weight: 1
        $x_1_6 = "DACls.pdb" ascii //weight: 1
        $x_1_7 = "DACls.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPQN_2147898282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPQN!MTB"
        threat_id = "2147898282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 07 18 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 03 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 08 06 16 06 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 2b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_DL_2147899392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.DL!MTB"
        threat_id = "2147899392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {4e 65 77 20 4f 72 64 65 72 20 52 65 71 75 65 73 74 73 [0-15] 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_5_2 = "Telegram Desktop" ascii //weight: 5
        $x_5_3 = "Telegram FZ-LLC" ascii //weight: 5
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_SPJR_2147900806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPJR!MTB"
        threat_id = "2147900806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 7b 12 00 00 04 07 11 04 08 59 09 11 06 02 7b 12 00 00 04 03 7b 25 00 00 04 11 04 09 11 06 03 6f ?? ?? ?? 06 03 6f ?? ?? ?? 06 00 00 11 06 17 58 13 06 11 06 1a fe 04 13 07 11 07 2d c1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPAA_2147900976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPAA!MTB"
        threat_id = "2147900976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08 5d d2 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 11 11 11 2d 8b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPDX_2147901268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPDX!MTB"
        threat_id = "2147901268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 38 72 ff ff ff 0b 38 72 ff ff ff 06 38 73 ff ff ff 28 ?? ?? ?? 2b 38 6e ff ff ff 28 ?? ?? ?? 2b 38 69 ff ff ff 28 ?? ?? ?? 0a 38 64 ff ff ff 02 38 63 ff ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPZZ_2147901737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPZZ!MTB"
        threat_id = "2147901737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 1f 16 5d 91 61 07 11 07 91 11 05 58 11 05 5d 59 d2 9c 11 04 17 58 13 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPZV_2147901738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPZV!MTB"
        threat_id = "2147901738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 1f 16 5d 91 13 0c 08 11 05 11 0b 11 0c 61 08 11 0a 91 11 04 58 11 04 5d 59 d2 9c 06 17 58 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPYY_2147901986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPYY!MTB"
        threat_id = "2147901986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5d 59 d2 9c 00 00 11 06 17 58 13 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPYX_2147902064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPYX!MTB"
        threat_id = "2147902064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {91 61 08 11 ?? 17 58 20 ?? ?? ?? 00 5d 91 09 58 09 5d 59 d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXXP_2147902084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXXP!MTB"
        threat_id = "2147902084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 15 91 61 07 11 12 17 58 20 ?? ?? ?? 00 5d 91 08 58 08 5d 59 d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPEE_2147902212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPEE!MTB"
        threat_id = "2147902212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 61 07 06 17 58 20 ?? ?? ?? 00 5d 91 09 58 09 5d 59 d2 9c 06 17 58 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPPY_2147902268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPPY!MTB"
        threat_id = "2147902268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 61 07 11 11 20 ?? ?? ?? 00 5d 91 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 59 d2 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPFE_2147902364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPFE!MTB"
        threat_id = "2147902364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5d 59 d2 9c 00 11 05 17 58 13 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPDV_2147902459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPDV!MTB"
        threat_id = "2147902459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 61 07 11 0e 20 ?? ?? ?? 00 5d 91 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 59 d2 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPFF_2147902559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPFF!MTB"
        threat_id = "2147902559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d 91 59 20 ?? ?? ?? 00 58 13 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXB_2147902664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXB!MTB"
        threat_id = "2147902664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5d 91 61 13 0b 11 0b 08 11 05 17 58 11 04 5d 91 59 20 ?? ?? ?? 00 58 13 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXZ_2147902694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXZ!MTB"
        threat_id = "2147902694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5d 91 59 20 ?? ?? ?? 00 58 13 0b 07 11 09 11 0b 20 ?? ?? ?? 00 5d d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPNN_2147902847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPNN!MTB"
        threat_id = "2147902847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 61 07 11 04 17 58 09 5d 91 59}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPVG_2147903228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPVG!MTB"
        threat_id = "2147903228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5d 91 61 07 09 17 58 08 5d 91 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 13 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPCZ_2147903406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPCZ!MTB"
        threat_id = "2147903406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 02 0e 04 04 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPBP_2147904424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPBP!MTB"
        threat_id = "2147904424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d 91 61 28 ?? ?? ?? 0a 07 11 ?? 17 58 07 8e 69 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPVX_2147904940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPVX!MTB"
        threat_id = "2147904940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 20 00 01 00 00 58 20 00 01 00 00 5d 13 ?? 07 11 ?? 11 ?? 6a 5d d4 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_KAB_2147905523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.KAB!MTB"
        threat_id = "2147905523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 0e 07 0e 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SSXP_2147910176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SSXP!MTB"
        threat_id = "2147910176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0c 18 2c 09 11 0c 11 0a 6f ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 07 de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPXF_2147912150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPXF!MTB"
        threat_id = "2147912150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5d 91 0d 07 08 91 09 61 07 08 17 58 07 8e 69 5d 91}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPVF_2147912501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPVF!MTB"
        threat_id = "2147912501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 91 11 ?? 61 09 17 58 07 8e 69 5d 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AMAC_2147912833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AMAC!MTB"
        threat_id = "2147912833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b ?? 00 06 07 7e ?? 00 00 04 07 91 02 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe ?? 0c 08 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MBYX_2147914203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MBYX!MTB"
        threat_id = "2147914203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 91 11 ?? 61 06 17 58 11 ?? 5d 13 ?? 07 11 ?? 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_GPX_2147914243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.GPX!MTB"
        threat_id = "2147914243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 91 11 ?? 61 13 ?? 06 17 58 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPLF_2147914424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPLF!MTB"
        threat_id = "2147914424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 16 fe 01 13 05 11 05 2c 0c 02 11 04 02 11 04 91 1f 1d 61 b4 9c 11 04 17 d6 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPCK_2147914739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPCK!MTB"
        threat_id = "2147914739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 19 00 02 06 7e ?? 00 00 04 06 91 04 06 05 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPBF_2147915074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPBF!MTB"
        threat_id = "2147915074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 0e 00 00 04 6f ?? 00 00 0a 00 25 7e 0f 00 00 04 6f ?? 00 00 0a 00 0a 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 2b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SDRA_2147915611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SDRA!MTB"
        threat_id = "2147915611"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 06 7e 04 00 00 04 06 91 04 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SGRG_2147916099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SGRG!MTB"
        threat_id = "2147916099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 5d 91 13 07 07 11 06 08 5d 08 58 08 5d 91 11 07 61 13 08 11 06 17 58 08 5d 08 58 08 5d 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SGRG_2147916099_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SGRG!MTB"
        threat_id = "2147916099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 08 7e 04 00 00 04 08 91 03 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e 04 00 00 04 8e 69 fe 04 0d 09 2d d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SOVP_2147916344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SOVP!MTB"
        threat_id = "2147916344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 07 91 13 08 11 06 08 58 08 5d 13 09 07 11 09 91 11 08 61 13 0a 11 06 17 58 08 58 08 5d 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SJVP_2147916579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SJVP!MTB"
        threat_id = "2147916579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 20 11 28 61 19 11 1c 58 61 11 30 61 d2 9c 17 11 09 58 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPDL_2147917843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPDL!MTB"
        threat_id = "2147917843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 05 5d 05 58 05 5d 0a 03 06 91 0b 07 0e 04 61 0e 05 59 20 00 02 00 00 58 0c 08 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_GPD_2147918272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.GPD!MTB"
        threat_id = "2147918272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0d 08 5d 13 0e 07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SML_2147918329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SML!MTB"
        threat_id = "2147918329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nflzptummq" ascii //weight: 1
        $x_1_2 = "$a03f1576-8580-4ed5-9252-0b81728488e8" ascii //weight: 1
        $x_1_3 = {06 07 a3 02 00 00 01 28 05 00 00 06 dd 06 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SML_2147918329_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SML!MTB"
        threat_id = "2147918329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.vascocorretora.com.br/PPI/" ascii //weight: 1
        $x_1_2 = "GetByteArrayAsync" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SWDL_2147919404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SWDL!MTB"
        threat_id = "2147919404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 2c 0d 2b 0d 72 01 00 00 70 2b 0d 2b 12 2b 17 de 1b 73 8c 00 00 0a 2b ec 28 ?? ?? ?? 0a 2b ec 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SLPF_2147919405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SLPF!MTB"
        threat_id = "2147919405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 40 01 00 fe 04 13 09 11 09 2c 0e 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 20 00 40 01 00 fe 04 13 0a 11 0a 2c 0e 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a fe 04 13 0b 11 0b 2d 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SLDF_2147919546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SLDF!MTB"
        threat_id = "2147919546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 05 11 06 6f ?? ?? ?? 0a 13 07 07 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0f 20 fb 00 00 00 91 1f 09 5b 13 0e 38 55 fe ff ff 00 07 6f ?? ?? ?? 0a 20 00 40 01 00 fe 04 13 08 11 08 2c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_CZ_2147919845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.CZ!MTB"
        threat_id = "2147919845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\SnakeKeylogger\\" ascii //weight: 5
        $x_3_2 = "- Snake Tracker -" ascii //weight: 3
        $x_2_3 = "$%TelegramDv$" ascii //weight: 2
        $x_2_4 = "KeyLoggerEventArgs" ascii //weight: 2
        $x_2_5 = "\\discord\\Local Storage\\leveldb\\" ascii //weight: 2
        $x_2_6 = "wlan show profile" ascii //weight: 2
        $x_1_7 = "\\Kinza\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_8 = "\\Sputnik\\Sputnik\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_9 = "\\BlackHawk\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_10 = "get_encryptedPassword" ascii //weight: 1
        $x_1_11 = "get_encryptedUsername" ascii //weight: 1
        $x_1_12 = "get_timePasswordChanged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_SHPF_2147919937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SHPF!MTB"
        threat_id = "2147919937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 73 22 00 00 0a 0d 09 08 17 73 23 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 05 dd 29 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPSG_2147920430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPSG!MTB"
        threat_id = "2147920430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 0d 07 11 0d 91 11 04 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 0d 17 58 13 0d 11 0d 09 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SIK_2147920481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SIK!MTB"
        threat_id = "2147920481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 16 13 07 38 9c 00 00 00 00 07 11 06 11 07 6f 5d 00 00 0a 13 08 09 12 08 28 5e 00 00 0a 6f 5f 00 00 0a 00 09 12 08 28 60 00 00 0a 6f 5f 00 00 0a 00 09 12 08 28 61 00 00 0a 6f 5f 00 00 0a 00 20 00 1e 01 00 13 09 08 6f 62 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "DeleteTextbox.MainForms.resources" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
        $x_1_4 = "TextBoxMaskInput.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SVFG_2147920646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SVFG!MTB"
        threat_id = "2147920646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 20 ff 00 00 00 5f 13 20 11 04 11 20 95 d2 13 21 09 11 1f 07 11 1f 91 11 21 61 d2 9c 00 11 1f 17 58 13 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PNH_2147920671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PNH!MTB"
        threat_id = "2147920671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 11 05 11 06 6f ?? 00 00 0a 13 07 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 20 00 40 01 00 fe 04 13 08 11 08 2c 0e 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 20 00 40 01 00 fe 04 13 09 11 09 2c 0e 07 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 06 17 58 13 06 11 06 06 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d 8c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SJJG_2147920780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SJJG!MTB"
        threat_id = "2147920780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 51 2b 52 6f ?? ?? ?? 0a 0d 73 1c 00 00 0a 13 04 11 04 09 17 73 1d 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 10 00 de 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SJQA_2147920781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SJQA!MTB"
        threat_id = "2147920781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 13 11 11 1d 11 09 91 13 27 11 1d 11 09 11 22 11 27 61 11 1a 19 58 61 11 2f 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_STSG_2147921749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.STSG!MTB"
        threat_id = "2147921749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 18 fe 04 16 fe 01 13 05 11 05 2c 0e 03 12 00 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 19 fe 01 13 06 11 06 2c 0e 03 12 00 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SYRA_2147921758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SYRA!MTB"
        threat_id = "2147921758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 11 11 1d 11 09 91 13 27 11 1d 11 09 11 27 11 22 61 19 11 1a 58 61 11 2f 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AMD_2147921791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AMD!MTB"
        threat_id = "2147921791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 09 11 04 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0a 06 11 05 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 06 6f ?? 00 00 0a 10 00 de 0e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PPBH_2147921868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PPBH!MTB"
        threat_id = "2147921868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 06 7e 04 00 00 04 06 91 05 06 28 ?? ?? ?? 0a 04 6f ?? ?? ?? 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SIPF_2147922344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SIPF!MTB"
        threat_id = "2147922344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 18 5b 8d 25 00 00 01 0a 16 0b 11 06 1f 32 93 20 40 d9 00 00 59 13 05 2b b9 00 06 07 72 3d 04 00 70 03 07 18 5a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 1a 62 72 3d 04 00 70 03 07 18 5a 17 58 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 60 d2 9c 16 13 05 2b 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SIPA_2147922511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SIPA!MTB"
        threat_id = "2147922511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {63 d1 13 11 11 1d 11 09 91 13 27 11 1d 11 09 11 27 11 22 61 11 1a 19 58 61 11 2f 61 d2 9c 17 11 09}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_KAE_2147922747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.KAE!MTB"
        threat_id = "2147922747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 18 5a 6f ?? 00 00 0a 28 ?? 00 00 0a 1a 62 72 ?? ?? ?? ?? 03 08 18 5a 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 60 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SDDA_2147922767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SDDA!MTB"
        threat_id = "2147922767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e 04 00 00 04 8e 69 fe 04 0d 09 2d d9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SDDA_2147922767_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SDDA!MTB"
        threat_id = "2147922767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 19 8d 89 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 08}  //weight: 2, accuracy: Low
        $x_1_2 = {07 12 03 28 ?? 00 00 0a 12 03 28 ?? 00 00 0a 58 12 03 28 ?? 00 00 0a 58 58 0b 02 09 04 05 28 ?? 00 00 06 11 0a}  //weight: 1, accuracy: Low
        $x_1_3 = "StorePixelData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SUT_2147923004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SUT!MTB"
        threat_id = "2147923004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "IAsyncResult" ascii //weight: 1
        $x_1_3 = {06 07 a3 02 00 00 01 28 05 00 00 06 dd 06 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SMI_2147923080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SMI!MTB"
        threat_id = "2147923080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 12 02 28 da 00 00 0a 13 05 12 02 28 db 00 00 0a 13 06 12 02 28 dc 00 00 0a 13 07 1d 13 0f 38 38 ff ff ff 03 11 05 16 61 d2 6f dd 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "$41b75bfe-ea68-421e-82f3-c50c8f47e80a" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SMJ_2147923231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SMJ!MTB"
        threat_id = "2147923231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 06 07 6f bb 00 00 0a 0c 04 03 6f bc 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 05 11 05 2c 2f 00 03 19 8d 8f 00 00 01 25 16 12 02 28 bd 00 00 0a 9c 25 17 12 02 28 be 00 00 0a 9c 25 18 12 02 28 bf 00 00 0a 9c 6f c0 00 00 0a 00 00 2b 4c 09 16 fe 02 13 06 11 06 2c 42}  //weight: 1, accuracy: High
        $x_1_2 = "AgroFarm.WarehouseStatusReport.resources" ascii //weight: 1
        $x_1_3 = "$6bebd5ac-a72c-44b8-a7d9-f01c2ae75635" ascii //weight: 1
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PHJH_2147923243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PHJH!MTB"
        threat_id = "2147923243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 1d 11 09 11 22 11 27 61 19 11 1a 58 61 11 2f 61 d2 9c 17 11 09 58 13 09 11 27 13 1a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PPPV_2147923245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PPPV!MTB"
        threat_id = "2147923245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0c 2b 19 00 02 08 7e ?? ?? ?? ?? 08 91 03 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? ?? ?? ?? 8e 69 fe 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPSB_2147923336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPSB!MTB"
        threat_id = "2147923336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 2c 00 00 0a 0c 08 07 17 73 2d 00 00 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 04 dd 27 00 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AMK_2147923391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AMK!MTB"
        threat_id = "2147923391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 09 11 04 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0a 06 11 05 17 73 ?? 00 00 0a 0c 08 [0-20] 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPDT_2147923742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPDT!MTB"
        threat_id = "2147923742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 73 22 00 00 0a 0d 09 06 07 6f ?? 00 00 0a 13 04 73 24 00 00 0a 13 05 11 05 11 04 17 73 25 00 00 0a 13 06 11 06 08 16 08 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SMV_2147923974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SMV!MTB"
        threat_id = "2147923974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$6bebd5ac-a72c-44b8-a7d9-f01c2ae75635" ascii //weight: 1
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Bitmap" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SCCF_2147924428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SCCF!MTB"
        threat_id = "2147924428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 13 06 03 11 06 09}  //weight: 3, accuracy: Low
        $x_2_2 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 09 19}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SKL_2147924445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SKL!MTB"
        threat_id = "2147924445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 06 07 28 aa 00 00 06 0c 04 03 6f a0 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 8d 7e 00 00 01 25 16 12 02 28 a1 00 00 0a 9c 25 17 12 02 28 a2 00 00 0a 9c 25 18 12 02 28 a3 00 00 0a 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_KAG_2147924769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.KAG!MTB"
        threat_id = "2147924769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 5a 58 20 00 01 00 00 5e 13 05 04 08 03 08 91 05 09 95 61 d2 9c 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SZZF_2147925150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SZZF!MTB"
        threat_id = "2147925150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c 6f ?? 01 00 0a 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 01 00 0a 59 0d 03 08 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MBXZ_2147925819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MBXZ!MTB"
        threat_id = "2147925819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 07 28 ?? ?? ?? 06 0c 04 03 6f ?? ?? ?? 0a 59 0d 03 08 09 28 ?? ?? ?? 06 00 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SVJA_2147926330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SVJA!MTB"
        threat_id = "2147926330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PPE_2147927163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PPE!MTB"
        threat_id = "2147927163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 0d 09 08 7e ?? ?? ?? 04 5a 20 00 01 00 00 5d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 0d 09 18 28 ?? ?? ?? 06 0d 09 66 20 ff 00 00 00 5f 0d 09}  //weight: 2, accuracy: Low
        $x_2_2 = "ainvestinternational.com/ajax/grid/Gothams.hm" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SVPF_2147927414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SVPF!MTB"
        threat_id = "2147927414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 06 07 6f ?? 00 00 0a 13 05 16 2d ef 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 1c 2c 1d 11 07 09 16 09 8e 69 6f ?? 00 00 0a 16 2d 0e 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 de 27 11 07 2c 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SKI_2147927766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SKI!MTB"
        threat_id = "2147927766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 13 07 11 07 16 30 02 2b 33 03 19 8d 44 00 00 01 25 16 12 02 28 53 00 00 0a 9c 25 17 12 02 28 54 00 00 0a 9c 25 18 12 02 28 55 00 00 0a 9c 09 28 01 00 00 2b 6f 56 00 00 0a 00 2b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "$87bc7c54-c779-43c3-b464-aeca864530b8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PKRH_2147928269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PKRH!MTB"
        threat_id = "2147928269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 11 09 7e ?? 00 00 04 11 09 91 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 11 09 07 8e 69 5d 91 61 d2 9c 00 11 09 17 58 13 09 11 09 7e ?? 00 00 04 8e 69 fe 04 13 0a 11 0a 2d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPKA_2147928297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPKA!MTB"
        threat_id = "2147928297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0a de 09 26 28 ?? 00 00 2b 0a de 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_MBWH_2147928905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.MBWH!MTB"
        threat_id = "2147928905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 13 10 16 13 16}  //weight: 2, accuracy: Low
        $x_1_2 = {73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SZA_2147929237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SZA!MTB"
        threat_id = "2147929237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 11 08 7e 08 00 00 04 11 08 91 28 46 00 00 0a 28 1f 00 00 06 6f 47 00 00 0a 11 08 28 46 00 00 0a 28 1f 00 00 06 6f 47 00 00 0a 8e 69 5d 91 61 d2 9c 00 11 08 17 58 13 08 11 08 7e 08 00 00 04 8e 69 fe 04 13 09 11 09 2d b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_KAK_2147929390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.KAK!MTB"
        threat_id = "2147929390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 0d 03 19 8d ?? 00 00 01 25 16 11 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 08 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 0d 19 8d ?? 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 13 09 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PLYH_2147929685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PLYH!MTB"
        threat_id = "2147929685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {1f 0a fe 02 0d 09 2c 06 72 ?? 00 00 70 0b 19 8d ?? 00 00 01 25 16 08 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 08 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 08 20 ?? 00 00 00 5f d2 9c 13 04 2b 00 11 04 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0d 2b 00 09 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_KAL_2147929773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.KAL!MTB"
        threat_id = "2147929773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 08 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {06 18 5a 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SYDF_2147929780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SYDF!MTB"
        threat_id = "2147929780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 08 20 ff 00 00 00 5f d2 9c 13 04}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SSUB_2147929988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SSUB!MTB"
        threat_id = "2147929988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 08 8f 4d 00 00 01 25 47 04 20 ff 00 00 00 5f d2 61 d2 52 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d de}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPRA_2147931996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPRA!MTB"
        threat_id = "2147931996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 03 16 03 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 de 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SZZ_2147933364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SZZ!MTB"
        threat_id = "2147933364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 20 00 f6 01 00 0d 20 ef be ad de 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PHH_2147933872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PHH!MTB"
        threat_id = "2147933872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 00 44 00 35 00 41 00 39 00 3a 00 30 00 33 00 3a 00 3a 00 30 00 34 00 3a 00 3a 00 46 00 46 00 46 00 46 00 3a 00 30 00 42 00 38 00 3a 00 3a 00 3a 00 3a 00 30 00 30 00 34 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 3a 00 30 00 30 00 38 00 3a 00 3a 00 30 00 30 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_BN_2147934284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.BN!MTB"
        threat_id = "2147934284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User Data\\Default\\EncryptedStorage" wide //weight: 1
        $x_1_2 = "User Data\\Default\\Login Data" wide //weight: 1
        $x_1_3 = "All User Profile * : (?<after>.*)" wide //weight: 1
        $x_1_4 = "wlan show profile name=" wide //weight: 1
        $x_1_5 = "Key Content * : (?<after>.*)" wide //weight: 1
        $x_1_6 = "key=clear" wide //weight: 1
        $x_1_7 = "Password:" wide //weight: 1
        $x_2_8 = "encrypted_key\":\"(.*?)" wide //weight: 2
        $x_2_9 = "SeaMonkey" wide //weight: 2
        $x_2_10 = "-------- Snake Track" wide //weight: 2
        $x_2_11 = "discord\\Local Storage\\leveldb" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SnakeKeylogger_SEDA_2147934365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SEDA!MTB"
        threat_id = "2147934365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? ?? 00 0a 9c 25 17 0f 00 28 ?? ?? 00 0a 9c 25 18 0f 00 28 ?? ?? 00 0a 9c 6f ?? ?? 00 0a 00 00 2b 15}  //weight: 3, accuracy: Low
        $x_2_2 = {02 03 04 6f ?? ?? 00 0a 0b 0e 04 05 6f ?? ?? 00 0a 59 0c 07 08 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SLP_2147935151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SLP!MTB"
        threat_id = "2147935151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 72 bd 04 00 70 6f ab 00 00 0a 75 29 00 00 01 0b 73 ac 00 00 0a 0c 20 00 0e 01 00 0d 07 08 09 28 38 00 00 06 00 d0 2b 00 00 01 28 a6 00 00 0a 72 c7 04 00 70 20 00 01 00 00 14 14 17 8d 12 00 00 01 25 16 08 6f ad 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {00 06 08 08 6c 28 b3 00 00 0a 6f b4 00 00 0a 00 00 08 18 58 0c 08 1f 0a fe 02 16 fe 01 0d 09 2d df}  //weight: 1, accuracy: High
        $x_1_3 = "BdayBuddy.Loading.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_HHB_2147935205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.HHB!MTB"
        threat_id = "2147935205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {02 03 04 6f ?? 00 00 0a 0b 0e 04 05 6f ?? 00 00 0a 59 0c 06 12 01 28 ?? 00 00 0a 1f 0a 5d 03 1f 0a 5a 04 58 6f ?? 00 00 0a 00 07 08 05}  //weight: 8, accuracy: Low
        $x_2_2 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SLO_2147935818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SLO!MTB"
        threat_id = "2147935818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 20 00 7e 01 00 0d 07 08 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SLO_2147935818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SLO!MTB"
        threat_id = "2147935818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 74 1e 00 00 01 11 05 11 0a 75 07 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 07 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 22 00 00 0a 26 19 13 0e 38 4c fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "$C285B947-A63D-4FC8-BC17-E9A4F1D782C0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RVA_2147935966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RVA!MTB"
        threat_id = "2147935966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6a 00 00 00 09 00 00 00 8a 00 00 00 48 00 00 00 5e 00 00 00 a2 00 00 00 1e 00 00 00 1d 00 00 00 03 00 00 00 06 00 00 00 09 00 00 00 04 00 00 00 01 00 00 00 07 00 00 00 06 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "Grifindo_payroll_system" ascii //weight: 1
        $x_1_3 = "d62f21fa-6585-4032-948b-0f030e94b773" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_GNT_2147936227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.GNT!MTB"
        threat_id = "2147936227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 72 09 0b 00 70 06 72 09 0b 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 9d 00 08 17 58 0c 08 02 fe 04 0d 09 2d d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PAA_2147936286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PAA!MTB"
        threat_id = "2147936286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 1b 11 0e 8f 05 00 00 01 25 47 11 0e 1f 1f 5a d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 08 75 ?? 00 00 1b 8e 69 32 d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SGPZ_2147936302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SGPZ!MTB"
        threat_id = "2147936302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 12 00 00 0a 0b 07 72 ?? 00 00 70 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ZHX_2147937141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ZHX!MTB"
        threat_id = "2147937141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EANK_2147937526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EANK!MTB"
        threat_id = "2147937526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 94 13 0b 11 04 11 0b 19 5a 11 0b 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 0a 17 58 13 0a 11 0a 11 09}  //weight: 5, accuracy: High
        $x_5_2 = {11 07 11 07 1f 11 5a 11 07 18 62 61 ?? ?? ?? ?? ?? 60 9e 11 07 17 58 13 07 11 07 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SWA_2147937545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SWA!MTB"
        threat_id = "2147937545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 72 9f 00 00 70 03 07 94 8c 36 00 00 01 04 07 94 8c 36 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 07 17 58 0b 07 03 16 6f ?? 00 00 0a fe 02 16 fe 01 0c 08 2d c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SJHA_2147937748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SJHA!MTB"
        threat_id = "2147937748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 08}  //weight: 3, accuracy: Low
        $x_2_2 = {02 11 05 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 07 72 ?? ?? ?? 70 28 ?? 00 00 0a 2c 08 11 09 1f 64 fe 02 2b 01}  //weight: 2, accuracy: Low
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SFDA_2147938389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SFDA!MTB"
        threat_id = "2147938389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 1e 0f 00 28 ?? 00 00 0a 0c 2b 18 0f 00 28 ?? 00 00 0a 0c 2b 0e 0f 00 28 ?? 00 00 0a 0c 2b 04 16 0c 2b 00 08 2a}  //weight: 2, accuracy: Low
        $x_1_2 = {02 11 05 11 07 6f ?? 00 00 0a 13 08 09 17 58 0d 05 13 0a 11 0a 39 ?? 00 00 00 00 11 04 13 0b 11 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RVB_2147939152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RVB!MTB"
        threat_id = "2147939152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 82 00 00 00 3b 00 00 00 49 03 00 00 82 02 00 00 42 02 00 00 2c 01 00 00 9f 01 00 00 01 00 00 00 83 00 00 00 0c 00 00 00 64 00 00 00 c5 00 00 00 19 00 00 00 01 00 00 00 01 00 00 00 09 00 00 00 17 00 00 00 04 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "6d6d6f58-52b9-4c6f-8a9b-407cbae81d75" ascii //weight: 1
        $x_1_3 = "SBMS.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_BAA_2147939508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.BAA!MTB"
        threat_id = "2147939508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 11 07 11 08 91 6f 8a 00 00 0a 11 08 17 58 13 08 11 08 11 06 32 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EAGI_2147939536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EAGI!MTB"
        threat_id = "2147939536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 47 11 0e 1f 1f 5a d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_PGS_2147940186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.PGS!MTB"
        threat_id = "2147940186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 20 00 7c 01 00 0d 07 08 09 28 ?? 00 00 06 00 17 8d ?? 00 00 01 25 16 1f 4c 9d 17 8d ?? 00 00 01 25 16 1f 6f 9d 28 ?? 00 00 2b 17 8d ?? 00 00 01 25 16 1f 61 9d 28 ?? 00 00 2b 17 8d ?? 00 00 01 25 16 1f 64 9d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ZHU_2147942086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ZHU!MTB"
        threat_id = "2147942086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 fe 04 16 fe 01 13 10 11 10 2c 2e 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 50 00 00 0a 6f ?? 00 00 0a 00 00 2b 58}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SL_2147942284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SL!MTB"
        threat_id = "2147942284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 07 8e 69 5d 13 11 07 11 11 11 0f 11 10 91 9c 03 11 0f 11 10 91 6f 4d 00 00 0a 08 17 58 07 8e 69 5d 0c 11 10 17 58 13 10 11 10 11 0d 32 d1}  //weight: 2, accuracy: High
        $x_2_2 = "ParkMaster.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EJKC_2147943987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EJKC!MTB"
        threat_id = "2147943987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 07 8e 69 5d 13 0e 07 11 0e 11 0b 9c 11 0e 17 58 07 8e 69 5d}  //weight: 1, accuracy: High
        $x_1_2 = {08 07 8e 69 5d 13 11 07 11 11 11 0f 11 10 91 9c 03 11 0f 11 10 91 ?? ?? ?? ?? ?? 08 17 58 07 8e 69 5d 0c 11 10 17 58 13 10 11 10 11 0d 32 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_RVC_2147944136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.RVC!MTB"
        threat_id = "2147944136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 17 b6 09 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 5d 00 00 00 10 00 00 00 60 00 00 00 44 00 00 00 1e 00 00 00 01 00 00 00 84 00 00 00 1a 00 00 00 15 00 00 00 01 00 00 00 01 00 00 00 03 00 00 00 08 00 00 00 0e 00 00 00 04 00 00 00 01 00 00 00 05 00 00 00 01 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "4B1E8AE6-09C8-4480-8399-3D1740EAE277" ascii //weight: 1
        $x_1_3 = "SecureMode.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_SPT_2147944909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.SPT!MTB"
        threat_id = "2147944909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SecureMode.Properties.Resources" wide //weight: 2
        $x_1_2 = "$4B1E8AE6-09C8-4480-8399-3D1740EAE277" ascii //weight: 1
        $x_1_3 = "1.6.1908.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_AD_2147945004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.AD!MTB"
        threat_id = "2147945004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 7d 2f 00 00 04 06 20 48 34 55 0e 5a 20 91 3e c5 e7 61 2b bc 02 03 7d 33 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_STO_2147945503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.STO!MTB"
        threat_id = "2147945503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 0e 07 0e 06 1b 23 ea e4 97 9b 77 e3 f9 3f 28 ?? 00 00 06 0b 02 03 04 06 05 0e 04 07 0e 08 23 39 b4 c8 76 be 9f e6 3f 28 ?? 00 00 06 00 00 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d b3}  //weight: 2, accuracy: Low
        $x_2_2 = {00 05 07 0e 06 23 00 00 00 00 00 00 e0 3f 19 28 ?? 00 00 06 0c 02 05 07 6f ?? 00 00 0a 0d 03 04 09 08 06 05 07 23 9a 99 99 99 99 99 b9 3f 17 28 ?? 00 00 06 00 0e 04 05 07 23 7b 14 ae 47 e1 7a 84 3f 17 28 ?? 00 00 06 00 00 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 13 04 11 04 2d 97}  //weight: 2, accuracy: Low
        $x_2_3 = "QLDTDD_FPT.Mainform.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EKER_2147946278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EKER!MTB"
        threat_id = "2147946278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 31 11 32 91 13 33 03 11 33 ?? ?? ?? ?? ?? 11 32 17 58 13 32 11 32 19 32 e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EKEQ_2147946279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EKEQ!MTB"
        threat_id = "2147946279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 11 39 fe 01 13 3a 11 3a 13 3b 11 3b 2c 0b 00 03 11 39 ?? ?? ?? ?? ?? 00 00 00 11 37 17 58 13 37 11 37 11 35 8e 69 fe 04 13 3c 11 3c 2d bb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EHGU_2147946281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EHGU!MTB"
        threat_id = "2147946281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 9a 09 08 17 58 6c 09 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 03 5a a1 00 09 17 58 0d 09 02 fe 04 13 04 11 04 2d d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_EHFM_2147946282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.EHFM!MTB"
        threat_id = "2147946282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0c 91 11 0c 1e 5a 1f 1f 5f 62 58 0a 00 11 0c 17 58 13 0c 11 0c 03 ?? ?? ?? ?? ?? 8e 69 1a ?? ?? ?? ?? ?? fe 04 13 0d 11 0d 2d cc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeylogger_ENYU_2147947297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogger.ENYU!MTB"
        threat_id = "2147947297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 04 18 5a 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 05 6c 5b ?? ?? ?? ?? ?? 02 ?? ?? ?? ?? ?? 5a 13 05 04 2c 09 11 04 04 8e 69 fe 04 2b 01 16 13 06 11 06 2c 0c 00 11 05 04 11 04 98 6c 5a 13 05 00 06 ?? ?? ?? ?? ?? 11 04 11 05 ?? ?? ?? ?? ?? a1 00 11 04 17 58 13 04 11 04 05 fe 04 13 07 11 07 2d 9e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

