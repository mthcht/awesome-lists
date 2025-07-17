rule Trojan_MSIL_SpyNoon_AR_2147772592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AR!MTB"
        threat_id = "2147772592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 11 13 20 00 04 00 00 58}  //weight: 4, accuracy: High
        $x_1_2 = "HF44P78RZ48JUYIBGG54P4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AN_2147772839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AN!MTB"
        threat_id = "2147772839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 2b 61 12 04 28 05 00 00 0a 0a 7e 03 00 00 04 72 0a 06 00 70 28 06 00 00 0a 28 07 00 00 0a 0b 07 06 6f 08 00 00 0a de 0a 07 2c 06 07 6f 09 00 00 0a dc 72 1c 06 00 70 0c 17 0d 09 2c 11 08 28 04 00 00 06 72 7a 06 00 70 28 0a 00 00 0a 0c 7e 03 00 00 04 72 80 06 00 70 28 06 00 00 0a 08 28 0b 00 00 0a 12 04 28 0c 00 00 0a 2d 96}  //weight: 2, accuracy: High
        $x_1_2 = "HARDWARE\\Description\\System\\CentralProcessor\\0" wide //weight: 1
        $x_1_3 = "Someone Opened Your Stealer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MR_2147773166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MR!MTB"
        threat_id = "2147773166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 1f 00 d0 [0-4] 28 [0-4] 72 [0-4] 18 1b 8d [0-4] 25 16 72 [0-4] a2 25 17 20 [0-4] 8c [0-4] a2 25 1a 17 8d [0-4] 25 16 03 74 [0-4] 28 [0-4] a2 a2 28 [0-4] 74 [0-4] 13 20 02 11 20 72 [0-4] 6f [0-4] 7d [0-4] 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_VA_2147773761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.VA!MTB"
        threat_id = "2147773761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "get_KeyValue" ascii //weight: 1
        $x_1_4 = "set_FileName" ascii //weight: 1
        $x_1_5 = "get_KeyCode" ascii //weight: 1
        $x_1_6 = "$32b7a984-595e-44ab-be0b-5642d2d40bee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_VA_2147773761_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.VA!MTB"
        threat_id = "2147773761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ropa.almacen.resources" ascii //weight: 1
        $x_1_2 = "Formulario.Kin.resources" ascii //weight: 1
        $x_1_3 = "FormularioAlumno.formAlumno.resources" ascii //weight: 1
        $x_1_4 = "FormularioAlumno.aceptarAlumno.resources" ascii //weight: 1
        $x_1_5 = "Ropa.ventas.resources" ascii //weight: 1
        $x_1_6 = "FormWindowState" ascii //weight: 1
        $x_1_7 = "GeneratedCodeAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "AssemblyProductAttribute" ascii //weight: 1
        $x_1_10 = "AssemblyCopyrightAttribute" ascii //weight: 1
        $x_1_11 = "AssemblyCompanyAttribute" ascii //weight: 1
        $x_1_12 = "ToByte" ascii //weight: 1
        $x_1_13 = "Dequeue" ascii //weight: 1
        $x_1_14 = "Enqueue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SA_2147773843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SA!MTB"
        threat_id = "2147773843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 02 8e 69 6a 5d d4 02 07 02 8e 69 6a 5d d4 91 06 07 06 8e 69 6a 5d d4 91 61 28 [0-4] 02 07 17 6a 58 02 8e 69 6a 5d d4 91 28 [0-4] 59 20 [0-4] 58 20 [0-4] 5e 28 [0-4] 9c 00 07 17 6a 58 0b 07 02 8e 69 17 59 6a 03 17 58 6e 5a fe 02 16 fe 01 0c 08 2d a0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SB_2147774144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SB!MTB"
        threat_id = "2147774144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c}  //weight: 10, accuracy: High
        $x_10_2 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RTU_2147777853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RTU!MTB"
        threat_id = "2147777853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggableAttribute" ascii //weight: 1
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "get_AllowOnlyFipsAlgorithms" ascii //weight: 1
        $x_1_4 = "SetWindowsHookEx" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_6 = "GetCursorInfo" ascii //weight: 1
        $x_10_7 = "$e2acb467-72ee-4e9b-950d-e2cfdb8a48d1" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RW_2147778098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RW!MTB"
        threat_id = "2147778098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$2ebe1629-7619-4e8a-9453-bf91b604b36c" ascii //weight: 10
        $x_10_2 = "GoldSrcWindowCtrls_Click" ascii //weight: 10
        $x_1_3 = "GoldSrcScheme.GoldSrcBtn.resources" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_6 = "GetProcessById" ascii //weight: 1
        $x_1_7 = "Win32Exception" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SpyNoon_RTH_2147778099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RTH!MTB"
        threat_id = "2147778099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_2 = "set_KeepPressed" ascii //weight: 1
        $x_1_3 = "$dec9efef-dfad-49e0-aaef-3322c983a256" ascii //weight: 1
        $x_1_4 = "Password :" ascii //weight: 1
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_6 = "HideModuleNameAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RF_2147786573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RF!MTB"
        threat_id = "2147786573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$7c158b45-9dc4-4066-8cda-58e028d1a857" ascii //weight: 10
        $x_1_2 = "<www.lumixsoft.com" ascii //weight: 1
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "MulticastDelegate" ascii //weight: 1
        $x_1_7 = "EditorBrowsableState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SpyNoon_SCDEFG_2147805125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SCDEFG!MTB"
        threat_id = "2147805125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 ac 05 d7 a6 20 7b 82 37 c7 61 25 0b 19 5e 45 03 00 00 00 e0 ff ff ff 18 00 00 00 02 00 00 00 2b 16 03 28 ?? ?? ?? 0a 0a 07 20 31 d4 3d 39 5a 20 6e e2 ab 4d 61 2b cd 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SHEBJK_2147805126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SHEBJK!MTB"
        threat_id = "2147805126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 16 03 28 ?? ?? ?? 0a 0a 07 20 f5 2f d4 71 5a 20 73 d1 7c 9d 61 2b cd 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_IYR_2147808637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.IYR!MTB"
        threat_id = "2147808637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 73 a9 00 00 0a 0b 28 ?? ?? ?? 06 0c 16 0d 2b 41 00 16 13 04 2b 27 00 08 09 11 04 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 13 09 07 09 11 09 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d ce 06 17 58 0a 00 09 17 58 0d 09 20 00 52 00 00 fe 04 13 0b 11 0b 2d b1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_LYR_2147808638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.LYR!MTB"
        threat_id = "2147808638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 0a 73 50 00 00 0a 0b 28 ?? ?? ?? 06 0c 16 0d 2b 41 00 16 13 04 2b 27 00 08 09 11 04 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 13 09 07 09 11 09 d2 6f ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d ce 06 17 58 0a 00 09 17 58 0d 09 20 00 7a 00 00 fe 04 13 0b 11 0b 2d b1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MB_2147809800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MB!MTB"
        threat_id = "2147809800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eergeegd2e" wide //weight: 1
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "YeeoShgdXjm9HMYMXoY" wide //weight: 1
        $x_1_4 = "CurrentDomain_UnhandledException" ascii //weight: 1
        $x_1_5 = "Form1_Load" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KEBBA_2147813205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KEBBA!MTB"
        threat_id = "2147813205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 e7 05 00 70 72 ec b5 00 70 72 f2 b5 00 70 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 06 0c 72 f8 b5 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 14 72 16 b6 00 70 28 ?? ?? ?? 0a 1b 8d 19 00 00 01 25 16 72 30 b6 00 70 28 ?? ?? ?? 0a a2 25 17 20 00 01 00 00 8c 77 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 08 a2 a2 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 74 06 00 00 1b 17 28 ?? ?? ?? 06 13 04 11 04 28 ?? ?? ?? 06 26 07 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPE_2147813313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPE!MTB"
        threat_id = "2147813313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download1481" wide //weight: 1
        $x_1_2 = "mediafire.com" wide //weight: 1
        $x_1_3 = "ENC.txt" wide //weight: 1
        $x_1_4 = "EntryPoint" wide //weight: 1
        $x_1_5 = "Invoke" wide //weight: 1
        $x_1_6 = "root.exe" wide //weight: 1
        $x_1_7 = "1A0571712A2F303411151A162C0A02322A2F2B7F" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPF_2147813314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPF!MTB"
        threat_id = "2147813314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hacking.Resources" wide //weight: 1
        $x_1_2 = "DownloadFile" wide //weight: 1
        $x_1_3 = "Environ" wide //weight: 1
        $x_1_4 = "jBOASPKQ38lJWJjzU4NKZsgmy0ZtbxBywap2NJ+hjRk" wide //weight: 1
        $x_1_5 = "JTm8ZN6YpsTGXXvN8VF7DAQTahLESh1BD9PcaqrdB6FqOaU" wide //weight: 1
        $x_1_6 = "6F5tLjtZeAb9nWrdKg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPG_2147813315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPG!MTB"
        threat_id = "2147813315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lockwood.rf.gd" wide //weight: 1
        $x_1_2 = "ENC.txt" wide //weight: 1
        $x_1_3 = "EntryPoint" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
        $x_1_5 = "HBankers" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "LateGet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KLNG_2147813721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KLNG!MTB"
        threat_id = "2147813721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ToString" ascii //weight: 2
        $x_2_2 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00}  //weight: 2, accuracy: High
        $x_2_3 = "FromBase64CharArray" ascii //weight: 2
        $x_2_4 = "ToCharArray" ascii //weight: 2
        $x_2_5 = {00 52 41 57 00}  //weight: 2, accuracy: High
        $x_2_6 = "DebuggableAttribute" ascii //weight: 2
        $x_2_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 2
        $x_2_8 = "DebuggerHiddenAttribute" ascii //weight: 2
        $x_2_9 = "DebuggerBrowsableAttribute" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MYA_2147813723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MYA!MTB"
        threat_id = "2147813723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {22 70 d6 9c cc 0a 22 ab ab 8a cc 0b 22 80 a3 32 cc 0a 07 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 72 7c 07 00 70 28 ?? ?? ?? 0a 72 d6 07 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0c 73 3c 00 00 06 0d 09 6f ?? ?? ?? 06 00 73 50 00 00 06 13 04 11 04 08 6f ?? ?? ?? 06 00 20 79 42 97 ff 13 05 20 35 ad cc fc 13 06 20 c9 55 8d ff 13 05 11 06 13 05 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_GLID_2147814759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.GLID!MTB"
        threat_id = "2147814759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 72 05 03 3d 72 3d 72 df 02 05 03 3d 72 e0 02 3d 72 3d 72}  //weight: 1, accuracy: High
        $x_1_2 = {f4 02 0f 03 ef 02 3d 72 eb 02 3d 72 3d 72 e3 02 3d 72 3d 72 cd 02 cd 02 d6 02}  //weight: 1, accuracy: High
        $x_1_3 = {df 02 d2 02 04 03 13 03 05 03 d2 02 df 02 12 03 df 02 0c 03 ec 02 e7 02 00}  //weight: 1, accuracy: High
        $x_2_4 = "FromBase64String" ascii //weight: 2
        $x_2_5 = "ToString" ascii //weight: 2
        $x_2_6 = "ToCharArray" ascii //weight: 2
        $x_2_7 = "GetAssemblies" ascii //weight: 2
        $x_2_8 = "Replace" ascii //weight: 2
        $x_2_9 = "ShakeOfTheDay" ascii //weight: 2
        $x_2_10 = "Invoke" ascii //weight: 2
        $x_2_11 = "GetType" ascii //weight: 2
        $x_2_12 = {00 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5a 00}  //weight: 2, accuracy: High
        $x_2_13 = {00 52 41 57 00}  //weight: 2, accuracy: High
        $x_2_14 = {00 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 00}  //weight: 2, accuracy: High
        $x_2_15 = {00 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 41 00}  //weight: 2, accuracy: High
        $x_2_16 = {00 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_YJX_2147814768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.YJX!MTB"
        threat_id = "2147814768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 8d 14 00 00 01 25 16 1f 23 9d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 57 00 00 01 25 16 02 a2 28 ?? ?? ?? 0a 74 59 00 00 01 0a 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MC_2147815314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MC!MTB"
        threat_id = "2147815314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 17 da 17 d6 8d ?? ?? ?? 01 0c 07 8e 69 17 da 13 06 16 13 07 2b 30 08 11 07 07 11 07 91 7e ?? ?? ?? 04 11 07 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 9c 11 07 17 d6 13 07 11 07 11 06 31}  //weight: 1, accuracy: Low
        $x_1_2 = "StartTestRun" ascii //weight: 1
        $x_1_3 = "ClearExtensions" ascii //weight: 1
        $x_1_4 = "proxyDiscoveryManager" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "GetLoggerManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_DWOF_2147817414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.DWOF!MTB"
        threat_id = "2147817414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 60 00 00 04 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 72 62 01 00 70 6f ?? ?? ?? 0a 1e 8d 42 00 00 01 17 73 50 00 00 0a 0b 73 51 00 00 0a 0c 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_FIFA_2147820209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.FIFA!MTB"
        threat_id = "2147820209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 0c 02 00 0b 38 13 00 00 00 00 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 3a df ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AA_2147820364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AA!MTB"
        threat_id = "2147820364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e 69 5d 91 07 58 20 ff 00 00 00 5f 61 d2 9c 08 17 58 0c 08 06 8e 69 17 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ME_2147822273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ME!MTB"
        threat_id = "2147822273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 03 8e 69 0b 2b 0a 06 07 03 07 91 6f ?? ?? ?? 0a 07 25 17 59 0b 16 fe 02 2d ec 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 0c 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = {3a 00 2f 00 2f 00 76 00 69 00 74 00 72 00 69 00 66 00 72 00 69 00 67 00 30 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_LOH_2147824777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.LOH!MTB"
        threat_id = "2147824777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 08 02 00 0b 2b 11 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_TTUF_2147825899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.TTUF!MTB"
        threat_id = "2147825899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 16 74 00 00 0c 2b 16}  //weight: 1, accuracy: High
        $x_1_2 = {07 08 28 06 01 00 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_CZUF_2147825911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.CZUF!MTB"
        threat_id = "2147825911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1a 58 4a 03 8e 69 5d 7e e7 00 00 04 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPC_2147835700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPC!MTB"
        threat_id = "2147835700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69 3f e1 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ANPZ_2147836107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ANPZ!MTB"
        threat_id = "2147836107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 24 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 30 00 00 0a 1f 10 28 31 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_NZQ_2147836457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.NZQ!MTB"
        threat_id = "2147836457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 8e 69 5d 91 09 17 6f ?? 00 00 0a 11 0a 91 61 9c 11 0a 17 d6 13 0a 11 0a 11 09 31 cb}  //weight: 1, accuracy: Low
        $x_1_2 = "KenPhasFuckedksajd44" ascii //weight: 1
        $x_1_3 = "cc/KF2bD1TM/stock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MF_2147839806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MF!MTB"
        threat_id = "2147839806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 0d 11 0d 11 03 94 11 0d 11 05 94 58 20 00 01 00 00 5d 94 13 06 38 e9 fe ff ff 11 04 17 58 13 04 38 38 fe ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "SortMerchant" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "PatchMerchant" ascii //weight: 1
        $x_1_5 = "://justnormalsite.ddns.net" wide //weight: 1
        $x_1_6 = "m8DAFE005B604C32" ascii //weight: 1
        $x_1_7 = "oaeb8e0581abb484cb6f83d53d975ea0d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ABOH_2147842937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ABOH!MTB"
        threat_id = "2147842937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "radarsystem.Properties.Resources.resources" ascii //weight: 3
        $x_1_2 = "radarsystem.Form1.resources" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_NSR_2147843463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.NSR!MTB"
        threat_id = "2147843463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 02 28 07 00 00 0a 28 ?? 00 00 06 00 09 28 ?? 00 00 06 00 07 28 ?? 00 00 06 13 04 de 2c}  //weight: 5, accuracy: Low
        $x_1_2 = "KostenminimalFluss" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ANA_2147844426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ANA!MTB"
        threat_id = "2147844426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 14 11 04 06 07 06 91 09 06 09 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 07 8e 69 32 e6}  //weight: 2, accuracy: High
        $x_1_2 = "IntersectionSim" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ANY_2147845475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ANY!MTB"
        threat_id = "2147845475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 14 2b 71 00 06 19 11 14 5a 6f ?? ?? ?? 0a 13 15 11 15 1f 39 fe 02 13 17 11 17 2c 0d 11 15 1f 41 59 1f 0a 58 d1 13 15 2b 08 11 15 1f 30 59 d1 13 15 06 19 11 14 5a 17 58 6f ?? ?? ?? 0a 13 16 11 16 1f 39 fe 02 13 18 11 18 2c 0d 11 16 1f 41 59 1f 0a 58 d1 13 16 2b 08 11 16 1f 30 59 d1 13 16 08 11 14 1f 10 11 15 5a 11 16 58 d2 9c 00 11 14 17 58 13 14 11 14 07 fe 04 13 19 11 19 2d 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASP_2147846426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASP!MTB"
        threat_id = "2147846426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b 2d 16 26 2b 3d 16 2b 3d 8e 69 16 2c 0e 26 26 26 2b 36 2b 0e 2b 35 2b da 0b 2b e8 28 ?? ?? ?? 0a 2b ee 2a 28 ?? ?? ?? 06 2b c4 28 ?? ?? ?? 0a 2b c3 06 2b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASP_2147846426_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASP!MTB"
        threat_id = "2147846426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {15 6a 16 28 ?? ?? ?? 0a 17 8d 3c 00 00 01 0b 07 16 17 9e 07 28 ?? ?? ?? 0a 02 02 7b 12 00 00 04 72 fb 00 00 70 15 16 28 ?? ?? ?? 0a 7d 11 00 00 04 02 6f ?? ?? ?? 06 02 7b 11 00 00 04 17 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASP_2147846426_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASP!MTB"
        threat_id = "2147846426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 14 fe 01 13 05 11 05 2c 11 72 c3 00 00 70 06 28 ?? ?? ?? 0a 73 2c 00 00 0a 7a 09 07 6f ?? ?? ?? 0a 13 04 11 04 14 fe 01 13 06 11 06 2c 11 72 e9 00 00 70 07 28 ?? ?? ?? 0a 73 2e 00 00 0a 7a 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASP_2147846426_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASP!MTB"
        threat_id = "2147846426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 2b 3b 07 08 9a 0d 00 09 6f ?? 00 00 0a 28 ?? 00 00 0a 16 fe 01 13 04 11 04 2c 1d 00 7e}  //weight: 2, accuracy: Low
        $x_1_2 = "james\\Desktop\\keylogger\\keylogger\\obj\\Debug\\keylogger.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MBCZ_2147846900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MBCZ!MTB"
        threat_id = "2147846900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 20 00 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 01 00 0a 13 05 08 11 05 6f ?? 01 00 0a 00 09 18 58 0d 00 09 07 6f ?? 01 00 0a fe 04 13 06 11 06 2d d1}  //weight: 1, accuracy: Low
        $x_1_2 = {72 76 25 00 70 06 72 82 25 00 70}  //weight: 1, accuracy: High
        $x_1_3 = {72 8c 25 00 70 72 23 04 00 70}  //weight: 1, accuracy: High
        $x_1_4 = {72 90 25 00 70 72 94 25 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPZ_2147847650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPZ!MTB"
        threat_id = "2147847650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 38 1c da ff ff 07 11 04 91 11 08 61 13 09 07 11 04 11 09 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPZ_2147847650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPZ!MTB"
        threat_id = "2147847650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 35 16 2c 23 26 2b 36 2b 3b 2b 3c 2b 41 ?? ?? ?? ?? ?? 1c 2d 16 26 2b 3d 16 2b 3d 8e 69 1c 2d 0e 26 26 26 2b 36 2b 0e 2b 35 2b da 0b 2b e8}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" wide //weight: 1
        $x_1_3 = "5.75.134.144" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AB_2147849342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AB!MTB"
        threat_id = "2147849342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 01 00 00 04 02 6f ?? 00 00 0a 0a 06 72 ?? 00 00 70 28}  //weight: 10, accuracy: Low
        $x_10_2 = {0f 00 28 1b 00 00 0a 0a 06 03 58 04 52}  //weight: 10, accuracy: High
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "HtmlDecode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASN_2147849824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASN!MTB"
        threat_id = "2147849824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 5d 16 0d 2b 18 7e 01 00 00 04 72 b7 00 00 70 28 ?? ?? ?? 0a 80 01 00 00 04 09 17 58 0d 09 03 32 e4}  //weight: 2, accuracy: Low
        $x_1_2 = "vt-client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASN_2147849824_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASN!MTB"
        threat_id = "2147849824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 2b 3d 17 13 08 16 13 09 2b 17 06 09 11 09 58 91 07 11 09 91 2e 05 16 13 08 2b 0d 11 09 17 58 13 09 11 09 07 8e 69 32 e2 11 08 2c 0f 08 09 6f ?? 00 00 0a 09 07 8e 69 58 0d 2b 04 09 17 58 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ABS_2147850255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ABS!MTB"
        threat_id = "2147850255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 0a 00 00 0a 0a 06 18 6f 0b 00 00 0a 00 06 18 6f 0c 00 00 0a 00 06 72 01 00 00 70 28 0d 00 00 0a 6f 0e 00 00 0a 00 06 6f 0f 00 00 0a 02 16 02 8e 69 6f 10 00 00 0a 0b 2b 00 07 2a}  //weight: 2, accuracy: High
        $x_2_2 = {00 28 11 00 00 0a 02 28 0d 00 00 0a 28 01 00 00 06 6f 12 00 00 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_2_3 = "HtmlDecode" ascii //weight: 2
        $x_2_4 = "FromBase64String" ascii //weight: 2
        $x_2_5 = "DownloadString" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAA_2147850829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAA!MTB"
        threat_id = "2147850829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 14 17 58 8c ?? ?? ?? ?? ?? ?? 00 00 0a 13 15 06 11 15 6f ?? ?? ?? ?? ?? ?? 00 00 1b 13 16 11 12 11 16 6f ?? 00 00 0a 11 14 17 58 13 14 11 14 1b 32 c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SP_2147851303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SP!MTB"
        threat_id = "2147851303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pSg9Q57kFPCMbkvjjEIWrg==" wide //weight: 1
        $x_1_2 = "P9ZGOlViJHqv8ctdpC6wwg==" wide //weight: 1
        $x_1_3 = "SYbgxJVA1op3c2nKigNEYA==" wide //weight: 1
        $x_1_4 = "vNKHq/DY69OMhhUmTCkDFw==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ASY_2147851859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ASY!MTB"
        threat_id = "2147851859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Google\\Chrome\\User Data\\Local State" wide //weight: 1
        $x_1_2 = "\\Google\\Chrome\\User Data" wide //weight: 1
        $x_1_3 = "\\Opera Software\\Opera Stable\\Local State" wide //weight: 1
        $x_1_4 = "\\Opera Software\\Opera Stable\\Login Data" wide //weight: 1
        $x_1_5 = "\\Microsoft\\Edge\\User Data\\Local State" wide //weight: 1
        $x_1_6 = "\\Microsoft\\Edge\\User Data" wide //weight: 1
        $x_1_7 = "SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins" wide //weight: 1
        $x_1_8 = "PK11SDR_Decrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAB_2147852103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAB!MTB"
        threat_id = "2147852103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 fe 01 2c 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 fe 04 2d cd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAB_2147852103_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAB!MTB"
        threat_id = "2147852103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 11 06 11 0a 11 06 8e 69 5d 11 06 11 0a 11 06 8e 69 5d 91 11 07 11 0a 1f 16 5d 6f ?? ?? 00 0a 61 28 ?? ?? 00 0a 11 06 11 0a 17 58 11 06 8e 69 5d 91 28 ?? ?? 00 0a 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d 28 ?? ?? 00 0a 9c 00 11 0a 15 58 13 0a 11 0a 16 fe 04 16 fe 01 13 0b 11 0b 2d a1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAA_2147888632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAA!MTB"
        threat_id = "2147888632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 07 00 00 04 28 05 00 00 06 0a 72 01 00 00 70 28 05 00 00 0a 00 06 28 06 00 00 0a 72 19 00 00 70 6f 07 00 00 0a 72 89 00 00 70 20 00 01 00 00 14 14 7e 0a 00 00 04 6f 08 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_1_2 = "lkoSe1ATx7XEIXKtAdTSwl1PKhNROoxstXsnsHTZbS2ikRLv6lmHd5v09DltsPeXIOA789wZC8qR1OScJFohGxuWQSQ8K2TAFUQAntIFdX" ascii //weight: 1
        $x_1_3 = "kjvvEHyOmySFEYdlfEyMxRIzhOn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ABAA_2147890136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ABAA!MTB"
        threat_id = "2147890136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Microsoft\\Windows\\Menu Start\\Programmi\\Esecuzione Automatica\\drivershandlers.exe" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\drivershandlers.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Neko\\Documents\\Visual Studio 2015\\Projects\\cartellator\\cartellator\\obj\\Debug\\cartellatorer.pdb" ascii //weight: 1
        $x_1_6 = "cartellatorer.exe" ascii //weight: 1
        $x_1_7 = "fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a24" ascii //weight: 1
        $x_1_8 = "cartellator.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAD_2147893927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAD!MTB"
        threat_id = "2147893927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 d2 20 ff 00 00 00 [0-30] 20 ff 00 00 00 5f 6a 61 d2 9c 11 ?? 17 6a 58 13 [0-10] 8e 69 17 59 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAD_2147893927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAD!MTB"
        threat_id = "2147893927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 13 06 72 ?? 01 00 70 72 ?? 02 00 70 72 ?? 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 09 11 05 14 14 11 06 6f ?? 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "##C##r#e##a#t##e#I##n#s##t#a##n#c##e#" ascii //weight: 1
        $x_1_3 = "DynamicPropertyObject.Properties.Resources" ascii //weight: 1
        $x_1_4 = "System.Net.Sockets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_UW_2147896358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.UW!MTB"
        threat_id = "2147896358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 11 05 6f 38 01 00 0a 17 73 18 01 00 0a 13 06 11 06 07 16 07 8e 69 6f 2d 01 00 0a 11 06 6f 2e 01 00 0a 11 04 6f 29 01 00 0a 28 39 01 00 0a 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ABOZ_2147896708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ABOZ!MTB"
        threat_id = "2147896708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 07 28 ?? ?? ?? 06 25 26 20 ?? ?? ?? 00 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 13 05 09 8e 69 8d ?? ?? ?? 01 13 06 11 05 11 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 11 06 8e 69 28 ?? ?? ?? 06 25 26 26 02 11 06 28 ?? ?? ?? 06 de 35}  //weight: 4, accuracy: Low
        $x_1_2 = "_007Stub.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAC_2147898988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAC!MTB"
        threat_id = "2147898988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 5, accuracy: Low
        $x_5_2 = "7C7E8DB70202" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MBFQ_2147898992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MBFQ!MTB"
        threat_id = "2147898992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 00 44 00 35 00 41 00 39 00 24 00 24 00 33 00 24 00 24 00 24 00 30 00 34 00 24 00 24 00 24 00 46 00 46 00 46 00 46 00 24 00 24 00 42 00 38 00 24 00 24 00 24 00 24}  //weight: 1, accuracy: High
        $x_1_2 = {24 00 24 00 30 00 38 00 24 00 24 00 24 00 24 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 24 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34 00 43 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMBF_2147899737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMBF!MTB"
        threat_id = "2147899737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0e 11 0f 61 13 10 07 11 0b 11 10 11 0d 59 11 09 5d d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMBG_2147899752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMBG!MTB"
        threat_id = "2147899752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0b 08 11 09 91 61 07 11 0a 91 59 11 0c 58 11 0c 5d 13 0d 07 11 08 11 0d d2 9c 11 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMBG_2147899752_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMBG!MTB"
        threat_id = "2147899752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 02 18 5d 3a ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 38 ?? 00 00 00 72 ?? 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 38}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0b 02 28 ?? 00 00 0a 0c 08 17 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_RPX_2147900039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.RPX!MTB"
        threat_id = "2147900039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "85.209.176.126" wide //weight: 1
        $x_1_2 = "BLACKLIST" wide //weight: 1
        $x_1_3 = "BaitDropper" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAF_2147900304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAF!MTB"
        threat_id = "2147900304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0C1F1B0D2084:::08185B09593" wide //weight: 1
        $x_1_2 = "117E13::040D190C084505:::08:::16" wide //weight: 1
        $x_1_3 = {07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMBA_2147901047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMBA!MTB"
        threat_id = "2147901047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1d 11 1a 59 13 1e 07 11 18 11 1e 11 16 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPZZ_2147901704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPZZ!MTB"
        threat_id = "2147901704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 0e 04 0e 09 02 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_GPA_2147902463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.GPA!MTB"
        threat_id = "2147902463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 58 09 5d 13 ?? 11 ?? 02 11 ?? ?? ?? ?? ?? 0a 11 09 61 d1 ?? ?? ?? ?? 0a 26 00 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPNN_2147902797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPNN!MTB"
        threat_id = "2147902797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0d 00 73 ?? ?? ?? 0a 13 04 09 11 04 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 0a de 2b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPDP_2147904015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPDP!MTB"
        threat_id = "2147904015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 5d d4 91 28 ?? ?? ?? 0a 59 11 07 58 11 07 5d 28 ?? ?? ?? 0a 9c 11 04 17 6a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMMB_2147904027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMMB!MTB"
        threat_id = "2147904027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 61 13 [0-15] 07 09 17 58 08 5d 91 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMMB_2147904027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMMB!MTB"
        threat_id = "2147904027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 61 6a 07 11 ?? 17 6a 58 07 8e 69 6a 5d d4 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPBP_2147904335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPBP!MTB"
        threat_id = "2147904335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d4 91 61 07 11 0e 11 0c 6a 5d d4 91 28 ?? ?? ?? 0a 59 11 0f 58 11 0f 5d 28 ?? ?? ?? 0a 9c 00 11 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPPO_2147904520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPPO!MTB"
        threat_id = "2147904520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {61 07 11 06 17 6a 58 07 8e 69 6a 5d d4 91}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPPO_2147904520_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPPO!MTB"
        threat_id = "2147904520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d4 91 61 07 11 ?? 17 6a 58 07 8e 69 6a 5d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAD_2147904894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAD!MTB"
        threat_id = "2147904894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5d d4 91 08 11 ?? 69 1f ?? 5d 6f ?? 00 00 0a 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MBZR_2147905036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MBZR!MTB"
        threat_id = "2147905036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 61 08 11 07 17 58 20 00 dc 00 00 5d 91 09 58 09 5d 59 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPBN_2147905099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPBN!MTB"
        threat_id = "2147905099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 13 ?? 08 11 ?? 11 ?? 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPPX_2147905446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPPX!MTB"
        threat_id = "2147905446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5d 13 06 07 11 06 91 13 07 08 09}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPPX_2147905446_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPPX!MTB"
        threat_id = "2147905446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 11 04 11 0c d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SDDF_2147906199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SDDF!MTB"
        threat_id = "2147906199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SUG_2147906340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SUG!MTB"
        threat_id = "2147906340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 09 91 11 06 61 13 07 07 09 11 07 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPCC_2147906721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPCC!MTB"
        threat_id = "2147906721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 91 13 09 08 11 07 91 13 0a 07 11 06 91 11 0a 61 13 0b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPCP_2147907032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPCP!MTB"
        threat_id = "2147907032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 13 09 07 11 04 11 09 07 11 07 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAE_2147907242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAE!MTB"
        threat_id = "2147907242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 06 07 93 1a 5b d1 9d 07 17 58 0b 07 06 8e 69 32 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPFV_2147908405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPFV!MTB"
        threat_id = "2147908405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 07 08 17 58 11 05 5d 91 59 20 00 01 00 00 58 13 06 07 08 11 06 20 ff 00 00 00 5f 28 ?? ?? ?? 0a 9c 08 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPNC_2147909252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPNC!MTB"
        threat_id = "2147909252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 07 11 0c 91 59 13 0d 11 0d 20 00 01 00 00 58 13 0e 07 11 09 11 0e 20 ff 00 00 00 5f d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SPXM_2147909510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SPXM!MTB"
        threat_id = "2147909510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 07 11 0d 91 59 13 0e 11 0e 20 00 01 00 00 58 13 0f 07 11 09 11 0f 20 ff 00 00 00 5f d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_GPAB_2147912688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.GPAB!MTB"
        threat_id = "2147912688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 91 11 [0-24] 61 [0-24] 06 17 58 07 8e 69 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAI_2147913005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAI!MTB"
        threat_id = "2147913005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 07 8e 69 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAJ_2147913846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAJ!MTB"
        threat_id = "2147913846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 00 43 00 68 00 6f 00 54 00 42 00 43 00 76 00 47 00 44 00 67 00 55 00 4f 00 42 00 47 00 45 00 66 00 66 00 56 00 6b 00 47 00 59 00 55 00 55 00 43}  //weight: 3, accuracy: High
        $x_3_2 = "8GF1gKDgQlWg0OBAlYDREG" wide //weight: 3
        $x_1_3 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAI_2147914638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAI!MTB"
        threat_id = "2147914638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 18 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 8e 69 8d ?? 00 00 01 13 04 02 73 ?? 00 00 0a 13 05 11 05 09 16 73 ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 12 04 11 07 28 ?? 00 00 2b de 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAJ_2147914966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAJ!MTB"
        threat_id = "2147914966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 07 06 91 11 ?? 61 13 ?? 07 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAJ_2147914966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAJ!MTB"
        threat_id = "2147914966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 17 58 20 ff 00 00 00 5f 0d 11 ?? 11 ?? 09 95 58 20 ff 00 00 00 5f}  //weight: 2, accuracy: Low
        $x_1_2 = {95 58 d2 13 [0-30] 20 ff 00 00 00 5f d2 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SCXM_2147915044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SCXM!MTB"
        threat_id = "2147915044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1f 16 5d 91 13 0c 11 06 11 08 91 11 0c 61 13 0d 11 06 11 08 17 58 11 07 5d 91 13 0e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAQ_2147916433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAQ!MTB"
        threat_id = "2147916433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 58 08 5d 13 [0-25] 61 [0-15] 17 58 08 58 08 5d [0-30] 08 58 08 5d 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SHVP_2147916728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SHVP!MTB"
        threat_id = "2147916728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 12 d4 91 13 15 11 07 11 04 95 11 07 11 05 95 58 d2 13 16 11 07 11 16 20 ff 00 00 00 5f 95 d2 13 17 11 15 11 17 61 13 18 11 08 11 12 d4 11 18 20 ff 00 00 00 5f d2 9c 11 18 13 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SYVP_2147916812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SYVP!MTB"
        threat_id = "2147916812"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 08 5d 08 58 08 5d 91 11 07 61 11 09 59 20 00 02 00 00 58 13 0a 16 13 1b 2b 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SGVP_2147916926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SGVP!MTB"
        threat_id = "2147916926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 91 13 15 11 07 11 04 95 11 07 11 05 95 58 d2 13 16 11 07 11 16 20 ff 00 00 00 5f 95 d2 13 17 11 15 11 17 61 13 18 11 08 11 12 d4 11 18 20 ff 00 00 00 5f d2 9c 11 18 13 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SXVP_2147917042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SXVP!MTB"
        threat_id = "2147917042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 06 91 11 07 61 11 09 59 20 00 02 00 00 58 13 0a 16 13 1b 2b 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAW_2147917298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAW!MTB"
        threat_id = "2147917298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 95 d2 13 [0-10] 61 [0-15] 20 ff 00 00 00 5f d2 9c 11 ?? 17 6a 58 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMAX_2147917341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMAX!MTB"
        threat_id = "2147917341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 5d 08 58 08 5d 13 [0-40] 61 [0-15] 59 20 00 02 00 00 58 [0-15] 20 00 01 00 00 5d 20 00 04 00 00 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SGRG_2147917712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SGRG!MTB"
        threat_id = "2147917712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 05 5d 05 58 05 5d 0a 03 06 91 0e 04 61 0e 05 59 20 00 02 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SFRG_2147918312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SFRG!MTB"
        threat_id = "2147918312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 5d 08 58 13 19 11 19 08 5d 13 1a 07 11 1a 91 13 1b 11 1b 11 12 61 13 1c 11 1c 20 00 04 00 00 58 13 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAK_2147918332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAK!MTB"
        threat_id = "2147918332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 5d 08 58 ?? ?? ?? ?? 08 5d [0-20] 61 ?? ?? ?? ?? 20 00 04 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_PPA_2147918636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.PPA!MTB"
        threat_id = "2147918636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 09 11 04 28 ?? ?? ?? 06 13 05 02 11 04 08 28 ?? ?? ?? 06 13 06 02 07 11 06 08 28 ?? ?? ?? 06 13 07 02 07 11 04 08 11 05 11 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_PPF_2147918637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.PPF!MTB"
        threat_id = "2147918637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 09 8e 69 5d 09 8e 69 58 13 07 11 07 09 8e 69 5d 13 08 09 11 08 91 13 09 11 06 17 58 08 5d 13 0a 11 0a 08 58 13 0b 11 0b 08 5d 13 0c 11 0c 08 5d 08 58 13 0d 11 0d 08 5d 13 0e 07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 11 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SCPF_2147918989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SCPF!MTB"
        threat_id = "2147918989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 10 11 0e 11 10 61 13 11 11 07 11 08 d4 11 11 20 ff 00 00 00 5f 28 30 00 00 0a 9c 11 08 17 6a 58 13 08}  //weight: 5, accuracy: High
        $x_4_2 = {5d d4 91 13 0d 11 04 11 0d 58 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SLFP_2147920360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SLFP!MTB"
        threat_id = "2147920360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 11 07 6f ?? ?? ?? 0a 13 08 09 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 00 1e 01 00 13 09 08 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 58 11 09 30 09 08 09 6f ?? ?? ?? 0a 2b 1f 11 09 08 6f ?? ?? ?? 0a 59 13 0a 11 0a 16 31 0f 08 09 16 11 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 11 07 17 58 13 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_STGK_2147923117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.STGK!MTB"
        threat_id = "2147923117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 16 fe 02 13 05 11 05 2c 40 00 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 fe 02 13 06 11 06 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 18 fe 02 13 07 11 07 2c 0e 03 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 03 6f ?? ?? ?? 0a 04 fe 04 16 fe 01 13 08 11 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SZDF_2147925634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SZDF!MTB"
        threat_id = "2147925634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 15 11 15 1f 7b 61 20 ff 00 00 00 5f 13 16 11 16 20 c8 01 00 00 58 20 00 01 00 00 5e 13 16 11 16 16 fe 01 13 17}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_MBWB_2147926196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.MBWB!MTB"
        threat_id = "2147926196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 20 00 c0 00 00 0d 07 08 09}  //weight: 2, accuracy: High
        $x_1_2 = "Load" wide //weight: 1
        $x_1_3 = {64 00 72 00 63}  //weight: 1, accuracy: High
        $x_1_4 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SOZA_2147926925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SOZA!MTB"
        threat_id = "2147926925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 0c 08 19 32 4d 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_KAY_2147927089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.KAY!MTB"
        threat_id = "2147927089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "_380BFEFFFF11_0" wide //weight: 3
        $x_4_2 = "0638CAFFFFFF11017E0701" wide //weight: 4
        $x_5_3 = "__112B05285EB11555380A" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SGTA_2147927237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SGTA!MTB"
        threat_id = "2147927237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_AMCS_2147928073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.AMCS!MTB"
        threat_id = "2147928073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 12 0c 28 ?? 00 00 0a 9c 25 17 12 0c 28 ?? 00 00 0a 9c 25 18 12 0c 28 ?? 00 00 0a 9c}  //weight: 4, accuracy: Low
        $x_1_2 = {1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_SKK_2147929014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.SKK!MTB"
        threat_id = "2147929014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {63 d1 13 1b 11 18 11 0b 91 13 29 11 18 11 0b 11 29 11 22 61 19 11 1d 58 61 11 2f 61 d2 9c}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_NITs_2147932223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.NITs!MTB"
        threat_id = "2147932223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CopyFromScreen" ascii //weight: 2
        $x_2_2 = "CaptureAndSendScreenshot" ascii //weight: 2
        $x_2_3 = "SendToDiscordWebhookAsync" ascii //weight: 2
        $x_1_4 = "GetProcessesByName" ascii //weight: 1
        $x_1_5 = "targetProcessNames" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_SpyNoon_NS_2147939636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.NS!MTB"
        threat_id = "2147939636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6f e7 00 00 0a 07 1f 10 8d 24 00 00 01 25 d0 0a 01 00 04 28 99 00 00 0a 6f e8 00 00 0a 06 07 6f e9 00 00 0a 17 73 6c 00 00 0a 0c 08 02 16 02 8e 69 6f ea 00 00 0a 08 6f eb 00 00 0a 06 28 bf 01 00 06 0d 09}  //weight: 3, accuracy: High
        $x_1_2 = "USBWallet.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ZJS_2147944576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ZJS!MTB"
        threat_id = "2147944576"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 14 72 d9 3b 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? 00 00 0a 13 0e 11 0e 2d c4 11 04 6f ?? 01 00 0a 0b 2b 00 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyNoon_ZTR_2147946643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyNoon.ZTR!MTB"
        threat_id = "2147946643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyNoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 05 06 6f ?? 00 00 0a 0b 23 00 00 00 00 00 80 41 40 23 00 00 00 00 00 00 14 40 28 ?? 00 00 06 58 0c 08 23 33 33 33 33 33 33 e3 3f 5a 0d 12 01 28 ?? 00 00 0a 12 01}  //weight: 6, accuracy: Low
        $x_5_2 = {59 13 09 11 09 19 32 29 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 3b 11 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

