rule Trojan_MSIL_Stelega_PAA_2147773280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.PAA!MTB"
        threat_id = "2147773280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FxResources.System.Security.Cryptography.ProtectedData" ascii //weight: 1
        $x_1_2 = "get_Cryptography_DpApi_ProfileMayNotBeLoaded" ascii //weight: 1
        $x_1_3 = "get_ArgumentMustBeGreaterThanOrEqualTo" ascii //weight: 1
        $x_1_4 = "get_ArgumentMustBeLessThanOrEqualTo" ascii //weight: 1
        $x_1_5 = "get_ArgumentUriHasQueryOrFragment" ascii //weight: 1
        $x_1_6 = "get_ArgumentInvalidHttpUriScheme" ascii //weight: 1
        $x_1_7 = "RegNotifyChangeKeyValue" ascii //weight: 1
        $x_1_8 = "HttpStyleUriParser" ascii //weight: 1
        $x_1_9 = "xXxXxXxXxXxXxXxQ" wide //weight: 1
        $x_1_10 = "WriteByte" ascii //weight: 1
        $x_1_11 = ".zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DB_2147777537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DB!MTB"
        threat_id = "2147777537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerPoint_Tools.Baidu.resources" ascii //weight: 1
        $x_1_2 = "PowerPoint_Tools.Resources" ascii //weight: 1
        $x_1_3 = "PowerPoint Tools" ascii //weight: 1
        $x_1_4 = "SmuggledMethodReturnMessage" ascii //weight: 1
        $x_1_5 = "StaticArrayInitTypeSize" ascii //weight: 1
        $x_1_6 = "Enter new connection string:" ascii //weight: 1
        $x_1_7 = "DebuggerAttached" ascii //weight: 1
        $x_1_8 = "_Lambda$__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DC_2147779333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DC!MTB"
        threat_id = "2147779333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 16 fe 01 13 04 11 04 2c 15 03 6f 7b 00 00 0a 09 6f 84 00 00 0a 6f 85 00 00 0a 0b 00 2b 1f 00 07 72 ?? ?? ?? 70 03 6f 7b 00 00 0a 09 6f 84 00 00 0a 6f 85 00 00 0a 28 55 00 00 0a 0b 00 09 17 d6 0d 09 08 31 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 08 28 46 00 00 0a 72 ?? ?? ?? 70 16 28 5d 00 00 0a 16 fe 03 0d 09 39 fa 00 00 00 08 28 46 00 00 0a 72 ?? ?? ?? 70 15 16 28 5e 00 00 0a 0c 08 74 6a 00 00 01 17 28 60 00 00 0a 18 fe 01 13 04 11 04 39 bf 00 00 00 08 17 8d 19 00 00 01 25 16 16 8c 6c 00 00 01 a2 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DF_2147779813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DF!MTB"
        threat_id = "2147779813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$542cab06-bc48-4594-9fb8-3926ed31a294" ascii //weight: 20
        $x_20_2 = "$06eee637-d14e-4d4e-b3d5-18f38a1d521a" ascii //weight: 20
        $x_5_3 = "CreateInstance" ascii //weight: 5
        $x_5_4 = "Activator" ascii //weight: 5
        $x_1_5 = "Audio_Realtek_Drive.Resources.resources" ascii //weight: 1
        $x_1_6 = "Gamer_Clock.My.Resources" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "DebuggableAttribute" ascii //weight: 1
        $x_1_13 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stelega_DG_2147779814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DG!MTB"
        threat_id = "2147779814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$818d92f8-ca83-4992-99c7-efc78e65f909" ascii //weight: 20
        $x_1_2 = "PixelSorter.Properties.Resources" ascii //weight: 1
        $x_1_3 = "cookie_list.txt" ascii //weight: 1
        $x_1_4 = "outlook.txt" ascii //weight: 1
        $x_1_5 = "passwords.txt" ascii //weight: 1
        $x_1_6 = "history_Mozilla Firefox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DI_2147782975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DI!MTB"
        threat_id = "2147782975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 0c 08 2d cf}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DJ_2147783079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DJ!MTB"
        threat_id = "2147783079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 2b 13 03 06 03 06 91 06 20 48 0a 00 00 5d 61 d2 9c 06 17 58 0a 06 03 8e 69 32 e7 02 03 7d ?? ?? ?? 04 1f 58 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DK_2147783080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DK!MTB"
        threat_id = "2147783080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 0c 08 2d cf}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "xoredString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DL_2147787432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DL!MTB"
        threat_id = "2147787432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MineSweeper_JSJ" ascii //weight: 1
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "smile win" ascii //weight: 1
        $x_1_4 = "get_X" ascii //weight: 1
        $x_1_5 = "get_Y" ascii //weight: 1
        $x_1_6 = ".Locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stelega_DN_2147793872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DN!MTB"
        threat_id = "2147793872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$e2acb467-72ee-4e9b-950d-e2cfdb8a48d1" ascii //weight: 20
        $x_20_2 = "$7c83c171-235c-499c-8a17-bd1662e9b6c4" ascii //weight: 20
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

rule Trojan_MSIL_Stelega_DA_2147899381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stelega.DA!MTB"
        threat_id = "2147899381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$8a474edc-6658-4fb0-891f-2ca9d5705ff4" ascii //weight: 1
        $x_1_2 = "|tram pn{not or-run v{-DOS z|qe." ascii //weight: 1
        $x_1_3 = "WavePad Sound Editor" ascii //weight: 1
        $x_1_4 = "NCH Software" ascii //weight: 1
        $x_1_5 = "connectionId" ascii //weight: 1
        $x_1_6 = ".NRaSrame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

