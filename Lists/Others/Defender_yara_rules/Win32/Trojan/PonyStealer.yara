rule Trojan_Win32_PonyStealer_V_2147743814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.V!MTB"
        threat_id = "2147743814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af 44 24 ?? c7 04 24 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 8b 0c 24 03 c8 89 0a 59 c2 06 00 51 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 67 ff ff ff 30 06 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_A_2147749921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.A!MSR"
        threat_id = "2147749921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08 89 1c 08}  //weight: 1, accuracy: High
        $x_2_2 = {85 f6 85 c0 85 db 33 1c 24 85 c9 90 85 c0 90 85 db}  //weight: 2, accuracy: High
        $x_1_3 = {85 f6 85 d2 85 f6 85 f6 85 f6 85 c0 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_VB_2147751355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "w7XvT3eB2utpaF32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "NIWVWfF14Pjh2Waldumns40" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Gf9Lm0F47SSibLlNiTGMAxqIuWb174" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "hVg529kYtQvTDVRcIPWVZPGHUDP182" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "JSTouVaHtsht4dCUHJ6wU9WZK9AiijU9wzFBkZbWTOmOj7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "GeH6V1WK4BsK123" wide //weight: 1
        $x_1_3 = "aql2eL237vTwXyg7cV8L93" wide //weight: 1
        $x_1_4 = "i0mz3ot80" wide //weight: 1
        $x_3_5 = {0f 6e c0 0f 6e 0b 0f ef c1 [0-21] 0f 7e c1 [0-37] 89 fb 89 04 0a 83 c1 [0-21] 8b 04 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_VB_2147751355_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 37 85 ff [0-64] [0-64] [0-64] 31 f1 [0-64] [0-64] 01 0c 10}  //weight: 4, accuracy: Low
        $x_2_2 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_3 = "WdHvQgDMTApwQB6sakX199" wide //weight: 1
        $x_1_4 = "Tfld72J3T6JOBgCcp7uzCNJjl5MBkKcna84" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_VB_2147751355_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "ERJZfjQxcUUXoi7sI6CsvDyj109" wide //weight: 1
        $x_1_3 = "efVGcMjSQqR1hGDeh3Lr7tU1Ed219" wide //weight: 1
        $x_1_4 = "nAGSNMYIx5Kt61iYqQIs23203" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "YetdfegDP105" wide //weight: 1
        $x_1_3 = "TkmdY9UCLVlgfxzIH02Yc148" wide //weight: 1
        $x_1_4 = "PUJveOZ2Rs164" wide //weight: 1
        $x_1_5 = "UCcjwDOE8ccwGh0i9N0TPD6VWUx215" wide //weight: 1
        $x_1_6 = "nDCkjvgUo9TwjiX7mV0or8lMq5ZsJlVRbhu52" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "jUd8jHJh5VAivAa8sweBpUzl9WThP142" wide //weight: 1
        $x_1_3 = "ald43EGUcycOi1OicyHkgaKP0khp1o6d37IgsvU100" wide //weight: 1
        $x_1_4 = "yeidUomBbvv1GUL68Pwv11zLp64" wide //weight: 1
        $x_1_5 = "Nl7pQ3Bn3oUIt1EWHYeapY2wfWTP84" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "sbeG0CVLnRoZ30Gfd7SkbII6huuJKdck88" wide //weight: 1
        $x_1_3 = "XmRCjm15qLPLcbAH9n6bSRQCLPgvTllGhBtSmHqq61" wide //weight: 1
        $x_1_4 = "ZJjVUFGrHvIWExkcMEHj7TrVZkbJI6l5rL42109" wide //weight: 1
        $x_1_5 = "KqfkTyqmkObQUfDuimBRAxgwWK2gJuHNJ0QtD42" wide //weight: 1
        $x_1_6 = "b3eyvwP0A8C2D9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_VB_2147751355_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "uiQYhwI7VBHGPo6rUbPbgNhf0RjFvtvdDXIYxWLWuMx420" wide //weight: 1
        $x_1_3 = "mb3EICvjZj6FDvtZGCF8jHP74" wide //weight: 1
        $x_1_4 = "FtgGKAf7zYEpyN8jVFW2GO60" wide //weight: 1
        $x_1_5 = "cG5xCKdpwItrj0SCOHwMitEcOP49" wide //weight: 1
        $x_1_6 = "JSTouVaHtsht4dCUHJ6wU9WZK9AiijU9wzFBkZbWTOmOj7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f9 81 ff [0-64] [0-64] [0-64] [0-64] 8b 09 [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f9 81 fa [0-64] [0-64] [0-64] [0-64] 8b 09 [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_3 = {89 f9 81 fb [0-64] [0-64] [0-64] [0-64] 8b 09 [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_4 = {89 f9 3d ea [0-64] [0-64] [0-64] [0-64] 8b 09 [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_5 = {89 f9 3d 6e [0-64] [0-64] [0-64] [0-64] 8b 09 [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 09 81 fb [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 09 81 fa [0-64] [0-64] 31 3c 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "veninderpendulumsdamnifi" wide //weight: 1
        $x_1_3 = "Zimmerwaldistatloidreolp9" wide //weight: 1
        $x_1_4 = "K6UdKOQs9n1xhanyoHrBFJ158" wide //weight: 1
        $x_1_5 = "CIVILISERINGSBEST" wide //weight: 1
        $x_1_6 = "Tapperierscornrickquaternitarianregaug" wide //weight: 1
        $x_1_7 = "OMPROGRAMMEREDEELSFORENKLINGSENSCON" wide //weight: 1
        $x_1_8 = "BCSonxCS8S38" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_VB_2147751355_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = {31 74 24 04}  //weight: 1, accuracy: High
        $x_1_3 = "WRJIF3hTRvbFk3YgRCXzt90" wide //weight: 1
        $x_1_4 = "yraNIYMw0Pg89DjVlHvleN9Vm95lGJZToKO60qrzKZGc00twhP189" wide //weight: 1
        $x_1_5 = "PIpWn957rsTMy7blL22bhEYjmf22" wide //weight: 1
        $x_1_6 = "n6sckM4IT1PdgwJwye1J2JYLvT262L8QYJdV2R6FSA185" wide //weight: 1
        $x_1_7 = "CbgVHQVf31RhBAK7VlwVlUCw9Ygg7Kb4iDrL2dDFbrdpG3135" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_VB_2147751355_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VB!MTB"
        threat_id = "2147751355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 fb 81 fa [0-64] [0-64] 8b 1b [0-64] [0-64] 31 34 24 [0-64] [0-64] [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_2 = {89 fb f7 c3 [0-64] [0-64] 8b 1b [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_3 = {89 fb f7 c1 [0-64] [0-64] 8b 1b [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_4 = {89 fb 81 ff [0-64] [0-64] 8b 1b [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_5 = {8b 1b f7 c3 [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_6 = {8b 1b f7 c1 [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_4_7 = {8b 1b f7 c6 [0-64] [0-64] 31 34 24 [0-64] 8f 04 10}  //weight: 4, accuracy: Low
        $x_1_8 = "v1NKtbpON2D0TTR8eUWNQzIs5nZRDPAtNAPq153" wide //weight: 1
        $x_1_9 = "W5lo33IJSflre1Ld2rleSwytQPkpB8OQJym8jFEwIccJH83" wide //weight: 1
        $x_1_10 = "k6lnCOH4BV66" wide //weight: 1
        $x_1_11 = "ycgfdi12Ui2eQ8Op6aw37FJyrs132" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_AE_2147751884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e c6 [0-37] 66 0f 6e c9 [0-64] 0f 7e c9 [0-37] 0f 77 [0-37] 46 [0-37] 8b 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e c6 [0-21] 66 0f 6e c9 [0-21] 66 0f ef c8 [0-21] 66 0f 7e c9 [0-37] 0f 77 [0-21] [0-21] ff 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e d0 0f 6e d0 0f 6e d0 [0-21] 46 [0-21] 8b 0f [0-21] 0f 6e c6 [0-21] 0f 6e c9 [0-21] 0f ef c8 [0-21] 0f 7e c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 7e d2 85 [0-37] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e d2 [0-21] 0f ef d7 [0-21] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 7e d2 83 [0-37] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e d2 [0-21] 0f ef d7 [0-21] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 7e d2 66 [0-37] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e d2 [0-21] 0f ef d7 [0-21] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 7e d2 66 [0-37] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e d2 [0-21] [0-21] 0f ef d7 [0-21] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 7e d2 85 [0-48] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e fe [0-37] 0f 6e d2 [0-37] [0-21] 0f ef d7 [0-37] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 7e d2 81 [0-48] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e fe [0-37] 0f 6e d2 [0-37] [0-21] 0f ef d7 [0-37] c3}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 7e d2 83 [0-48] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e fe [0-37] 0f 6e d2 [0-37] [0-21] 0f ef d7 [0-37] c3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 7e d2 66 [0-48] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e fe [0-37] 0f 6e d2 [0-37] [0-21] 0f ef d7 [0-37] c3}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 7e d2 3d [0-48] [0-21] 46 [0-21] 8b 17 [0-37] 0f 6e fe [0-37] 0f 6e d2 [0-37] [0-21] 0f ef d7 [0-37] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_AE_2147751884_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AE!MTB"
        threat_id = "2147751884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0f 6e da 3d [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_6_2 = {0f 6e da 81 [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_6_3 = {0f 6e da 66 [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_6_4 = {0f 6e da 83 [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_6_5 = {0f 6e da 85 [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_6_6 = {0f 6e da eb [0-64] 31 f1}  //weight: 6, accuracy: Low
        $x_1_7 = "CxsM3cO2z70VQJ2rHcK8iCcWDsgfqgBdXEHmttl240" wide //weight: 1
        $x_1_8 = "T0JiAaIaJKhN5bFNTB3VUBg1IcJ5jbHKYyENi11" wide //weight: 1
        $x_1_9 = "DVUze6RDyKfIJ7FbwuxJBpCg46vWecEw66" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PonyStealer_EM_2147753057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.EM!MTB"
        threat_id = "2147753057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "utQUzKERRxs4wWjxl9X126" wide //weight: 1
        $x_1_3 = "F31SoezeFKeOmxweyTRdPF2vKHM166" wide //weight: 1
        $x_1_4 = "QIcU1XvbVhDPbc3e9WdUVv172" wide //weight: 1
        $x_1_5 = "aqTdMpGPdsNZrUeypitRGcRGrn9zHan250" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_PB_2147753555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.PB!MTB"
        threat_id = "2147753555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MG__KVIS.exe" wide //weight: 1
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "Schuerger" ascii //weight: 1
        $x_1_4 = "Dacryelcosis" ascii //weight: 1
        $x_1_5 = "Balsamic" ascii //weight: 1
        $x_1_6 = "Visitation0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_T_2147754437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.T!MTB"
        threat_id = "2147754437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 1d c0 00 00 00 [0-4] 83 fb 00 74 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 0a d9 d0 01 f3 0f 6e c0 [0-16] 0f 6e 0b [0-16] 0f ef c1 51 0f 7e c1 [0-16] 88 c8 [0-16] 59 29 f3 83 c3 01 75 ?? [0-16] 89 fb 89 04 0a 83 c1 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_PC_2147754962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.PC!MTB"
        threat_id = "2147754962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chrome.exe" wide //weight: 1
        $x_1_2 = "Google Chrome" wide //weight: 1
        $x_1_3 = "Unsharable" wide //weight: 1
        $x_1_4 = "Entosclerite0" ascii //weight: 1
        $x_1_5 = "Gasterosteid8" ascii //weight: 1
        $x_1_6 = "vb4projectVb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_PE_2147755043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.PE!MTB"
        threat_id = "2147755043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Theatres" ascii //weight: 1
        $x_1_2 = "RAFTERED" ascii //weight: 1
        $x_1_3 = "mellemamerikansk" ascii //weight: 1
        $x_1_4 = "IBrF69XOSwZAaVa9svn82" wide //weight: 1
        $x_1_5 = "HZK1gcvFFbeLTjQhw2Z6xPlZaidU8wks89" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_SK_2147755290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.SK!MTB"
        threat_id = "2147755290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 70 80 11 00 00 04 72 07 00 00 70 80 12 00 00 04 2a}  //weight: 2, accuracy: High
        $x_2_2 = {0f 00 28 1e 00 00 06 0f 01 28 1e 00 00 06 fe 01 16 fe 01 2a}  //weight: 2, accuracy: High
        $x_1_3 = {2b 01 08 0c 00 20 ef 00 00 00 20 ee 00 00 00 28 01 00 00 2b 16 9a 14 16 8d 03 00 00 01 6f 1d 00 00 0a 26 17 13 07 38 b4 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_PD_2147755574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.PD!MTB"
        threat_id = "2147755574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 46 66 85 db ff 37 85 ff [0-111] 59 [0-16] 31 f1 [0-16] 39 c1 75}  //weight: 1, accuracy: Low
        $x_1_2 = {85 ff 46 81 fb ?? ?? ?? ?? ff 37 66 ?? ?? ?? ?? 59 [0-16] 31 f1 [0-16] 39 c1 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {66 85 db 46 81 fb ?? ?? ?? ?? ff 37 [0-191] 59 [0-16] 31 f1 [0-16] 39 c1 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_PA_2147756469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.PA!MTB"
        threat_id = "2147756469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b 0e 56}  //weight: 1, accuracy: High
        $x_1_2 = {5e 29 de 51}  //weight: 1, accuracy: High
        $x_1_3 = {59 31 c1 56}  //weight: 1, accuracy: High
        $x_1_4 = {5e 89 0c 1a 56}  //weight: 1, accuracy: High
        $x_1_5 = {5e 85 db 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_B_2147757575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.B!MTB"
        threat_id = "2147757575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0f 81 [0-32] 58 [0-32] e8 [0-32] 89 04 0f [0-32] 83 e9 fc [0-32] 75 [0-32] 57 [0-32] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 34 0f 66 [0-32] 58 [0-32] e8 [0-32] 89 04 0f [0-32] 83 e9 fc [0-32] 75 [0-32] 57 [0-32] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_VD_2147758600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VD!MTB"
        threat_id = "2147758600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f5 85 d2 [0-64] 8a 03 34 ?? 8b d6 03 d1 88 02}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f1 85 d2 [0-64] 8b 45 ?? 8a 80 ?? ?? ?? ?? 34 ?? 8b 55 ?? 03 55 ?? 88 02 [0-64] 8b 45 ?? 8a 80 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_VG_2147787481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.VG!MTB"
        threat_id = "2147787481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 f7 c1 d7 0b 31 34 24 f7 c2 0a 17 ce b5 81 fb 6b 19 ce b5 81 f9 cc 1b ce b5 81 fa bc 1d ce b5 66 81 fa 08 20 8f 04 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_SIB_2147794941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.SIB!MTB"
        threat_id = "2147794941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 54 24 10 75 ?? [0-32] [0-32] bb ?? ?? ?? ?? [0-32] [0-32] 4b [0-32] 4b [0-32] 4b [0-32] 4b [0-32] ff 34 1f [0-32] 5a [0-32] 56 [0-32] 33 14 24 [0-32] 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 54 24 10 75 ?? [0-32] [0-32] bb ?? ?? ?? ?? [0-32] [0-32] 4b [0-32] 4b [0-32] 4b [0-32] 4b [0-32] ff 34 1f [0-32] 5a [0-32] e8 ?? ?? ?? ?? [0-32] 89 14 18 [0-32] 85 db 0f 85 ?? ?? ?? ?? [0-32] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PonyStealer_EP_2147796806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.EP!MTB"
        threat_id = "2147796806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e9 04 81 fc 7b db 57 6e ff 34 0f 90 8f 04 08 81 fc 1f ed 57 6e 31 34 08 eb 08 00 00 00 00 00 00 00 00 85 c9 75 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_SIBA_2147796871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.SIBA!MTB"
        threat_id = "2147796871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 4d 5a 90 00 [0-5] 48 [0-10] 81 38 4d 5a 90 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {81 38 4d 5a 90 00 75 ?? [0-32] 8b 00 [0-5] 6a 40 [0-5] 68 00 ?? 00 00 [0-5] bf 00 c0 00 00 [0-5] 57 [0-5] 57 [0-5] 29 3c 24 [0-5] ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 0c 38 fc [0-5] 81 34 38 ?? ?? ?? ?? [0-5] 83 ef 04 [0-5] 8b 0c 3a [0-5] 89 0c 38 [0-5] 81 34 38 ?? ?? ?? ?? [0-5] 83 ef 04 7d ?? [0-5] ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_PonyStealer_BD_2147835778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.BD!MTB"
        threat_id = "2147835778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {35 8d b3 51 d1 32 7c 01 43 a2 cf 35 62 06 a5 b0 b8 4d d7 66 0e 35 77 57 38 41 3e 39 cc 7f}  //weight: 2, accuracy: High
        $x_2_2 = {4f d3 b3 30 3a 04 29 33 cf 97 87 a2 87 74 d6 24 91 82 b2 79 44 ba cd f5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_ARA_2147916546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.ARA!MTB"
        threat_id = "2147916546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 37 0f 65 f7 66 0f 6a d7 66 0f 71 f6 64 66 0f db f9 66 0f ec c6 66 0f 69 ce 0f df fd 66 0f 60 f0 66 0f dc fd 83 c7 04 0f eb e0 0f dd e7 66 0f df f5 0f 6b d9 0f 72 f3 f8 66 0f d8 db 0f 73 f5 c8 0f e5 d5 66 0f 72 d1 fe 81 7f fc 70 70 70 70 75 ae 0f 66 fe 66 0f e9 c6 0f 64 c8 0f f5 ea 5f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_GNK_2147916721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.GNK!MTB"
        threat_id = "2147916721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 0c fb ef be ?? ?? ?? ?? 49 32 0b 43 49}  //weight: 5, accuracy: Low
        $x_5_2 = {28 08 f0 00 00 34 d3 6b 0e dd eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_GTT_2147926908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.GTT!MTB"
        threat_id = "2147926908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 fc 97 31 48 cf 0c ff 3c a2 6b bb}  //weight: 5, accuracy: High
        $x_5_2 = {d0 31 33 07 d0 b4 68 ?? ?? ?? ?? c4 00}  //weight: 5, accuracy: Low
        $x_1_3 = "Braggat0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_EAOP_2147932051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.EAOP!MTB"
        threat_id = "2147932051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 10 8b d4 89 3a 8b 3d e4 10 40 00 89 42 04 89 72 08 6a 02 89 4a 0c 8b 55 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAA_2147935608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAA!MTB"
        threat_id = "2147935608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 0c 30 8a 09 80 f1 63 8d 1c 30 88 0b 90 90 40 4a 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAB_2147935609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAB!MTB"
        threat_id = "2147935609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 06 30 d8 f6 d0 46 04 62 c0 c0 04 04 8b 30 c3 66 59 88 0c 07 e9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAC_2147936775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAC!MTB"
        threat_id = "2147936775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 ff 66 31 34 24 3c 23 80 fd f4 66 81 fb ed 8f 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAD_2147937532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAD!MTB"
        threat_id = "2147937532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 45 f4 50 6a 04 8b 45 08 83 c0 38 50 8b 45 08 ff 70 34}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_GTB_2147939924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.GTB!MTB"
        threat_id = "2147939924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {47 57 00 01 00 08 00 39 48 57 00 01 00 08}  //weight: 5, accuracy: High
        $x_5_2 = {31 00 08 37 c8 9b fa a3 96 5f 43 91}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_GZZ_2147942338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.GZZ!MTB"
        threat_id = "2147942338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 00 19 01 00 42 00 21 fe f3 00 00 6c 74}  //weight: 5, accuracy: High
        $x_5_2 = {31 11 d1 22 14 1d 94 4d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_AHB_2147946296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.AHB!MTB"
        threat_id = "2147946296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {66 0f 76 f2 0f fa f2 0f 6f ff 41 0f eb d8 0f 71 f0 02 0f d5 d2 ff 73 2c 66 0f 74 c1 66 0f fe d9 0f fc ff 31 0c 24 66 0f 76 f2 0f fa f2 0f 6f ff 5a 0f eb d8 0f 71 f0 02 0f d5 d2 83 fa 00 75}  //weight: 3, accuracy: High
        $x_2_2 = {48 66 0f 74 c1 66 0f fe d9 0f fc ff 48 66 0f 76 f2 0f fa f2 0f 6f ff 48 0f eb d8 0f 71 f0 02 0f d5 d2 33 14 03 66 0f 74 c1 66 0f fe d9 0f fc ff e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAE_2147946311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAE!MTB"
        threat_id = "2147946311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 85 f0 fd ff ff 8c 23 00 00 c7 85 f4 fd ff ff 05 00 00 00 83 a5 30 ff ff ff 00 eb}  //weight: 2, accuracy: High
        $x_2_2 = {58 31 30 89 8d 80 00 00 00 b9 c3 13 9f 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PonyStealer_DAF_2147946312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyStealer.DAF!MTB"
        threat_id = "2147946312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 0f 64 c1 66 0f e8 d5 0f 73 f7 36 66 0f d5 f4 66 0f ef c4 66 0f 76 d7 66 0f fd d6 66 0f d8 c4 66 0f e9 c2 66 0f 64 e8 66 0f 67 c4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

