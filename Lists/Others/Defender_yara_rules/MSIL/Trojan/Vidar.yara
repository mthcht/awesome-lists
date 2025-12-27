rule Trojan_MSIL_Vidar_AF_2147787515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AF!MTB"
        threat_id = "2147787515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 25 33 00 16 ?? ?? 01 ?? ?? ?? 19 ?? ?? ?? 02 ?? ?? ?? 02 ?? ?? ?? 01 ?? ?? ?? 17 ?? ?? ?? 0a ?? ?? ?? 01 ?? ?? ?? 02 ?? ?? ?? 01}  //weight: 10, accuracy: Low
        $x_3_2 = "webClient" ascii //weight: 3
        $x_3_3 = "EnableVisualStyles" ascii //weight: 3
        $x_3_4 = "DownloadData" ascii //weight: 3
        $x_3_5 = "discord" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSc_2147830035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSc!MTB"
        threat_id = "2147830035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 15 a2 01 09 01 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2d 00 00 00 06 00 00 00 75 00 00 00 19 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "dRwe3J5uDff2BvBCwI" ascii //weight: 1
        $x_1_4 = "fPgH1EjEcKvoZ42CvX" ascii //weight: 1
        $x_1_5 = "r2UvkAOxmlOaND3sMc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSa_2147831467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSa!MTB"
        threat_id = "2147831467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 95 a2 29 09 09 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 31 00 00 00 08 00 00 00 0c 00 00 00 3b 00 00 00 02}  //weight: 5, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "get_ExecutablePath" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NV_2147836558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NV!MTB"
        threat_id = "2147836558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 10 63 20 ?? ?? ?? 00 5f d2 6f ?? ?? ?? 0a 19 13 0b 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "AnyDesk Installer.exe" ascii //weight: 1
        $x_1_3 = "NpnadFBaaxom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NV_2147836558_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NV!MTB"
        threat_id = "2147836558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 8f 02 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 07 1f 10 8d ?? ?? 00 01 25 d0 ?? ?? 00 04 28 ?? ?? 00 0a 6f ?? ?? 00 0a 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 0c 08 02 16 02 8e 69 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ingenious_installation_solution" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NV_2147836558_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NV!MTB"
        threat_id = "2147836558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 0c 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 17 8d ?? 00 00 01 0d 09 16 17 8d ?? 00 00 01 25 13 04 11 04 16 7f ?? 00 00 04 d3 16 58 47 69 20 ?? 00 00 00 61 9d 73 ?? 00 00 0a a2 09 16 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "urchinsSapful" ascii //weight: 1
        $x_1_3 = "sapfulWisp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NV_2147836558_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NV!MTB"
        threat_id = "2147836558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 01 00 00 04 06 7e ?? ?? ?? 04 8e 69 6a 5d d4 91 7e ?? ?? ?? 04 06 7e ?? ?? ?? 04 8e 69 6a 5d d4 91 61 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 06 17 6a 58 7e ?? ?? ?? 04 8e 69 6a 5d d4 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 28 ?? ?? ?? 0a 9c 00 06 17 6a 58 0a 06 7e ?? ?? ?? 04 8e 69 17 59 1c 5a 6a fe 02 16 fe 01 0b 07 3a ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "://github.com/sparta137/crypts/raw/main/E32" wide //weight: 1
        $x_1_3 = "Ian.FrmMaze.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NEAA_2147836652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NEAA!MTB"
        threat_id = "2147836652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {a2 25 18 09 a2 25 19 17 8c 25 00 00 01 a2 13 04 14 13 05 07 28 1d 00 00 0a 72 79 01 00 70 6f 1e 00 00 0a}  //weight: 10, accuracy: High
        $x_5_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" wide //weight: 5
        $x_5_3 = "aHR0cHM6Ly9vbmUubGl0ZXNoYXJlLmNvL2Rvd25sb2FkLnBocD9pZD1QSDA0S1RU" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_A_2147837085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.A!MTB"
        threat_id = "2147837085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 1d 00 00 01 13 2d 20 00 01 00 00 8d 1d 00 00 01 13 2e 11 04 6e 11 14 6a 30 0c 08 09 5a 13 20 11 2b 11 07 59 13 14 11 21 11 20 31 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_A_2147837085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.A!MTB"
        threat_id = "2147837085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de 09 69 8d 36 00 00 01 25 17 73 11 00 00 0a 13 04 06 6f 12 00 00 0a 1f 0d 6a 59}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_5 = "NtResumeThread" ascii //weight: 1
        $x_1_6 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_7 = "NtWriteVirtualMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RDA_2147837699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RDA!MTB"
        threat_id = "2147837699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d672ef0d-95b2-4490-89b8-789a939dfad2" ascii //weight: 1
        $x_2_2 = {11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_GCD_2147838084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.GCD!MTB"
        threat_id = "2147838084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 7e 01 00 00 04 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b 02 28 ?? ?? ?? 0a 0c 07 08 16 08 8e 69 6f ?? ?? ?? 0a 0d 09 13 04 de 0b}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MBN_2147838132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MBN!MTB"
        threat_id = "2147838132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0c 08 06 7d ?? 00 00 04 00 07 7e ?? 00 00 04 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 08 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RDB_2147838225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RDB!MTB"
        threat_id = "2147838225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 20 ?? ?? ?? ?? 58 9e 11 17}  //weight: 2, accuracy: Low
        $x_2_2 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54}  //weight: 2, accuracy: High
        $x_1_3 = "d672ef0d-95b2-4490-89b8-789a939dfad2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_GCS_2147838512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.GCS!MTB"
        threat_id = "2147838512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IDpD0KK69V9p12ie" ascii //weight: 1
        $x_1_2 = "YJ234j8hTZD59PoO" ascii //weight: 1
        $x_1_3 = "kZnhTKDdklaIBEZkOacn" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NR_2147838699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NR!MTB"
        threat_id = "2147838699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 2d 06 d0 5d ?? ?? 06 26 06 07 6f ?? ?? ?? 0a 25 26 0c 1f 61 6a 08 28 ?? ?? ?? 06 25 26 0d 09 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "annotation.optimization.CriticalNative.module6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_B_2147839114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.B!MTB"
        threat_id = "2147839114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 0a 00 06 18 6f ?? ?? 00 0a 00 06 18 6f ?? ?? 00 0a 00 06 6f ?? ?? 00 0a 0b 02 28 ?? ?? 00 0a 0c 07 08 16 08 8e 69 6f ?? ?? 00 0a 0d 09}  //weight: 2, accuracy: Low
        $x_2_2 = {00 0a 00 06 18 6f ?? ?? 00 0a 00 06 18 6f ?? ?? 00 0a 00 06 6f ?? ?? 00 0a 0b 07 02 16 02 8e 69 6f ?? ?? 00 0a 0c 08 28 ?? ?? 00 0a 0d de}  //weight: 2, accuracy: Low
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "LoadLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_C_2147839115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.C!MTB"
        threat_id = "2147839115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de 09 69 8d 37 00 00 01 25 17 73 11 00 00 0a 13 04 06 6f 12 00 00 0a 1f 0d 6a 59}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "CreateRemoteThread" ascii //weight: 1
        $x_1_4 = "Wow64SetThreadContext" ascii //weight: 1
        $x_1_5 = "NtResumeThread" ascii //weight: 1
        $x_1_6 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_7 = "NtWriteVirtualMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NEAB_2147839466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NEAB!MTB"
        threat_id = "2147839466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 11 0d 16 11 0b 6f cb 00 00 0a 26 11 0a 11 0d 16 11 0b 11 0c 16 6f e3 00 00 0a 13 0f 7e 5e 00 00 04 11 0c 16 11 0f 6f cf 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f 96 00 00 0a 32 bf}  //weight: 10, accuracy: High
        $x_2_2 = "CheckRemoteDebuggerPresent" wide //weight: 2
        $x_2_3 = "PrintActivator" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MBBI_2147839699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MBBI!MTB"
        threat_id = "2147839699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 0d 16 11 0b 6f ?? 00 00 0a 25 26 26 11 0a 11 0d 16 11 0b 11 0c 16 6f 8e 00 00 0a 25 26 13 0f 7e 35 00 00 04 11 0c 16 11 0f 6f 8f 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f 87 00 00 0a 25 26 32 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_SPAW_2147839707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.SPAW!MTB"
        threat_id = "2147839707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 37 00 00 0a 0b 1e 00 06 18 6f ?? ?? ?? 0a 06 6f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MA_2147840329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MA!MTB"
        threat_id = "2147840329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 02 16 02 8e 69 6f ?? ?? ?? 0a 00 07 6f 29 00 00 0a 00 06 6f ?? ?? ?? 0a 0c de 16 07 2c 07 07 6f 25 00 00 0a 00 dc 06 2c 07 06 6f 25 00 00 0a 00 dc 08 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {9c 25 17 1f 58 9c 13 08 11 05 1f 7b 28 ?? ?? ?? 0a 13 09 02 08 11 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MBAL_2147840358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MBAL!MTB"
        threat_id = "2147840358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 0a 2b 14 00 02 7b ?? 00 00 04 06 06 73 ?? 00 00 06 a2 00 06 17 58 0a 06 7e ?? 00 00 04 17 58 fe 04 0b 07 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_CQ_2147840478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.CQ!MTB"
        threat_id = "2147840478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 a4 00 00 06 28 89 ?? ?? ?? 72 3d 05 00 70 72 41 05 00 70 28 a5 00 00 06 72 49 05 00 70 72 4d 05 00 70 28 a5 00 00 06 72 51 05 00 70 72 01 05 00 70 6f 8a 00 00 0a 13 01 20 ?? ?? ?? ?? 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NH_2147840595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NH!MTB"
        threat_id = "2147840595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 26 0c 08 20 ?? ?? 00 00 28 ?? ?? 00 0a 25 26 0d 09 28 ?? ?? 00 0a 25 26 13 04 11 04 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Inacttyrants" ascii //weight: 1
        $x_1_3 = "Bww74" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVB_2147841373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVB!MTB"
        threat_id = "2147841373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28}  //weight: 5, accuracy: High
        $x_1_2 = "SnakesAndLadders.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVF_2147842029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVF!MTB"
        threat_id = "2147842029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 7b 16 00 00 04 17 6f ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "9amous.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVF_2147842029_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVF!MTB"
        threat_id = "2147842029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 37 00 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 0a 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "fa3a1684336017.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVS_2147842030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVS!MTB"
        threat_id = "2147842030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 26 00 00 0a 0c 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 13 04 08 11 04 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "DBDownloader" ascii //weight: 1
        $x_1_3 = "RawZipAndAes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_SPQ_2147843338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.SPQ!MTB"
        threat_id = "2147843338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 1b 8d 09 00 00 01 25 16 20 5c 04 00 00 28 ?? ?? ?? 06 a2 25 17 07 a2 25 18 20 74 04 00 00 28 ?? ?? ?? 06 a2 25 19 08 a2 25 1a 20 7e 04 00 00 28 ?? ?? ?? 06 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 38 46 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "ReceiveCaptureRequest" ascii //weight: 1
        $x_1_3 = "ReceiveEncryptionStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_GFT_2147843450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.GFT!MTB"
        threat_id = "2147843450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 06 16 73 ?? ?? ?? 0a 0c 00 02 8e 69 8d ?? ?? ?? 01 0d 08 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 09 11 04 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 05 de 21}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVA_2147843460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVA!MTB"
        threat_id = "2147843460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 76 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "Co7fere7ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVA_2147843460_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVA!MTB"
        threat_id = "2147843460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 11 07 16 73 ?? 00 00 0a 13 0b 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 fe 0c 09 00}  //weight: 5, accuracy: Low
        $x_1_2 = "final.Bridges.IndexerRepositoryBridge.resources" ascii //weight: 1
        $x_1_3 = "Qirhkrygb.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVA_2147843460_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVA!MTB"
        threat_id = "2147843460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 07 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 02 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 73 ?? 00 00 0a 28 ?? 00 00 06 03 6f ?? 00 00 0a 28 ?? 00 00 06 0c 08 73 ?? 00 00 0a 07 06 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 28 ?? 00 00 2b 16 fe 01}  //weight: 5, accuracy: Low
        $x_1_2 = "bouling4feet_member.My.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_D_2147843839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.D!MTB"
        threat_id = "2147843839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "yKaRG.uWgba.resources" ascii //weight: 2
        $x_2_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
        $x_2_3 = "0Q71J1NOK1iWOFeGet.y9taJQZUm4w9i7QF6q" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSJO_2147844710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSJO!MTB"
        threat_id = "2147844710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 0a 8f 09 00 00 02 11 0c 08 11 0a 8f 09 00 00 02 7b 2f 00 00 04 16 28 04 00 00 06 7d 34 00 00 04 17 73 7d 00 00 0a 08 11 0a 8f 09 00 00 02 7b 34 00 00 04 6f 34 00 00 0a 13 0d dd 14 fb ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RDF_2147844718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RDF!MTB"
        threat_id = "2147844718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "29ca28b0-6f30-42a4-97d5-4f65e2725471" ascii //weight: 1
        $x_1_2 = "weMU" ascii //weight: 1
        $x_2_3 = {fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 93 fe 09 02 00 61 d1 9d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_ABSR_2147845758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.ABSR!MTB"
        threat_id = "2147845758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 07 06 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 09 08 16 73 ?? 00 00 0a 13 04 02 8e 69 8d ?? 00 00 01 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 11 05 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 13 07 de 2a 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_FAR_2147845775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.FAR!MTB"
        threat_id = "2147845775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 00 20 00 00 00 00 7e ?? 09 00 04 7b ?? 09 00 04 39 ?? 00 00 00 26 20 00 00 00 00 38 ?? 00 00 00 fe ?? 03 00 45}  //weight: 2, accuracy: Low
        $x_2_2 = {38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 13 02 38 00 00 00 00 dd}  //weight: 2, accuracy: Low
        $x_1_3 = "Dcfehddavoyzhtccrdr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSLO_2147846176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSLO!MTB"
        threat_id = "2147846176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 3f 00 00 06 0a 06 28 5e 00 00 0a 7d 30 00 00 04 06 02 7d 32 00 00 04 06 03 7d 31 00 00 04 06 15 7d 2f 00 00 04 06 7c 30 00 00 04 12 00 28 03 00 00 2b 06 7c 30 00 00 04 28 60 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSMH_2147846245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSMH!MTB"
        threat_id = "2147846245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 6f 09 01 00 0a 11 06 6f 97 00 00 0a 16 73 c9 00 00 0a 13 0d 11 0d 11 07 28 59 03 00 06 de 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_ABTU_2147846303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.ABTU!MTB"
        threat_id = "2147846303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 16 00 03 28 ?? 00 00 06 0a 02 73 ?? 00 00 0a 0b 07 06 16 73 ?? 00 00 0a 0c 00 02 8e 69 8d ?? 00 00 01 0d 28 ?? 00 00 06 28 ?? 00 00 06 39 ?? 00 00 00 26 20 02 00 00 00 38 ?? 00 00 00 08 09 16 09 8e 69 28 ?? 00 00 06 13 04}  //weight: 2, accuracy: Low
        $x_1_2 = {09 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 dd ?? 00 00 00 08 39 ?? 00 00 00 08 6f ?? 00 00 0a 00 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MBCO_2147846416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MBCO!MTB"
        threat_id = "2147846416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 00 21 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 4b}  //weight: 1, accuracy: High
        $x_1_2 = "185.254.37.108" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MBDD_2147847142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MBDD!MTB"
        threat_id = "2147847142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 6b 66 66 66 66 00 67 64 64 64 66 66 64 73 64 68 66 73 73 66 64 67 68 00 66 68 66 73 64 73 64 66 73 66 66 68 66 64 64 66 68 68 73 00 68 73 66 66 66}  //weight: 1, accuracy: High
        $x_1_2 = "nhffskdgsfkdfffddadfrfffdfdhffscfdf" ascii //weight: 1
        $x_1_3 = "hkgfffgsddfffdhhddrfdafddsshcf" ascii //weight: 1
        $x_1_4 = "sgfhjffkfffgdhjsrfhddfhfffaddsfsfssfcfgdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSNX_2147847446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSNX!MTB"
        threat_id = "2147847446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 07 00 00 0a 73 b9 02 00 06 28 ba 02 00 06 75 01 00 00 1b 6f 08 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVC_2147847508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVC!MTB"
        threat_id = "2147847508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 0a 8d 02 00 00 01 25 0a 06 16 20 ?? ?? ?? 1a 20 ?? ?? ?? 1a 61 9d 06 17 20 ?? ?? ?? 6c 20 ?? ?? ?? 6c 61 9d 06 18 20 ?? ?? ?? 3e 20 ?? ?? ?? 3e 61 9d}  //weight: 5, accuracy: Low
        $x_1_2 = "TautensWmk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MB_2147847714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MB!MTB"
        threat_id = "2147847714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a de 03 26 de 00 06 2c 03 16 2b 03 17 2b 00 2d d5 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NBA_2147848255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NBA!MTB"
        threat_id = "2147848255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 04 11 07 1f 40 12 01 6f ?? ?? ?? 06 13 05 20 ?? ?? ?? 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 05 8e 69 13 07}  //weight: 5, accuracy: Low
        $x_1_2 = "VImjLwg0Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NAE_2147848437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NAE!MTB"
        threat_id = "2147848437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 16 9a 26 16 2d f9 00 28 ?? 00 00 06 20 ?? 00 00 00 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b}  //weight: 5, accuracy: Low
        $x_1_2 = "niderlandsdll_clameup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_ABYN_2147848552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.ABYN!MTB"
        threat_id = "2147848552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 16 02 7b ?? 00 00 04 8e 69 6f ?? 00 00 0a 0c 08 28 ?? 00 00 06 00 02 1e 00 07 02 7b}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_GAV_2147848718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.GAV!MTB"
        threat_id = "2147848718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 0a 38 26 00 00 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 08 00 00 06 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c d7}  //weight: 4, accuracy: Low
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 [0-5] 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 [0-5] 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Vidar_NVV_2147848734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVV!MTB"
        threat_id = "2147848734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 60 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? ?? 00 06 58}  //weight: 5, accuracy: Low
        $x_1_2 = "micropatch2dll_compleate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NNI_2147849604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NNI!MTB"
        threat_id = "2147849604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f a5 00 00 0a 0d 1a 13 0f 38 ?? ?? ?? ff 08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 1e 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "federalunderstanding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AACY_2147849630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AACY!MTB"
        threat_id = "2147849630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 08 28 ?? 04 00 06 25 17 28 ?? 04 00 06 25 18 6f ?? 00 00 0a 25 06 28 ?? 04 00 06 6f ?? 00 00 0a 07 16 07 8e 69 28 ?? 04 00 06 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AADB_2147849648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AADB!MTB"
        threat_id = "2147849648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 59 0a 06 20 10 0e 00 00 6a 5b 1f 18 6a 5d 80 ?? 00 00 04 06 20 10 0e 00 00 6a 59 0a 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 06 1f 3c 6a 59 0a 06 1f 3c 6a 5d 80 ?? 00 00 04 09 6f ?? 00 00 0a de 07 09 6f ?? 00 00 0a dc 08 6f ?? 00 00 0a 13 04 de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_MC_2147849935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.MC!MTB"
        threat_id = "2147849935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 25 17 58 0b 09 a4 24 00 00 02 08 17 58 0c 08 02 8e 69 32 95 06 07 16 16 28 ?? 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {57 17 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 58 00 00 00 2c 00 00 00 4f 00 00 00 99 00 00 00 80 00 00 00 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSRA_2147850088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSRA!MTB"
        threat_id = "2147850088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 11 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 03 38 41 00 00 00 02 1f 10 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 00 20 01 00 00 00 28 ?? ?? ?? 06 3a 27 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSRE_2147850234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSRE!MTB"
        threat_id = "2147850234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 09 28 a6 a6 6b 3e 14 16 9a 26 16 2d f9 fe 09 00 00 fe 09 01 00 fe 09 02 00 fe 09 03 00 6f 7a 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RDG_2147850261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RDG!MTB"
        threat_id = "2147850261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 07 59 06 6f 0d 00 00 0a 58 06 6f 0d 00 00 0a 5d 13 04 08 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSRH_2147850303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSRH!MTB"
        threat_id = "2147850303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {60 0c 28 1e 00 00 0a 7e 01 00 00 04 02 08 6f 1f 00 00 0a 28 20 00 00 0a a5 01 00 00 1b 0b 11 07 20 89 6e 9b 64 5a 20 d0 c5 ea 58 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AAGT_2147851427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AAGT!MTB"
        threat_id = "2147851427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d 09 13 04 11 04 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "DataBasePracticalJob" wide //weight: 1
        $x_1_3 = "EhsMCpLEkrOfkDrpUhiwfxv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AAIW_2147852354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AAIW!MTB"
        threat_id = "2147852354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 11 02 28 ?? ?? 00 06 25 17 28 ?? ?? 00 06 25 18 6f ?? 00 00 0a 25 11 00 6f ?? 00 00 0a 28 ?? ?? 00 06 11 04 16 11 04 8e 69 28 ?? ?? 00 06 13 03}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NHA_2147852423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NHA!MTB"
        threat_id = "2147852423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 16 00 00 01 28 ?? ?? 00 06 02 28 ?? ?? 00 06 75 ?? ?? 00 1b 28 ?? ?? 00 2b 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 06 28 ?? ?? 00 2b 28 ?? ?? 00 06 26 20 ?? ?? 00 00 7e ?? ?? 00 04 7b ?? ?? 00 04}  //weight: 5, accuracy: Low
        $x_1_2 = "believeintegrate.Stubs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NDV_2147852427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NDV!MTB"
        threat_id = "2147852427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 c8 00 00 0a 0d 08 74 ?? 00 00 01 16 73 ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 74 ?? 00 00 01 09 75 ?? 00 00 01 6f ?? 00 00 0a de 45 18 13 08}  //weight: 5, accuracy: Low
        $x_1_2 = "z5CJn0.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AALZ_2147888502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AALZ!MTB"
        threat_id = "2147888502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 1b 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANF_2147889053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANF!MTB"
        threat_id = "2147889053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 11 02 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 28 ?? 00 00 06 25 11 04 6f ?? 00 00 0a 28 ?? 00 00 06 11 01 16 11 01 8e 69 28 ?? 00 00 06 13 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANG_2147889054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANG!MTB"
        threat_id = "2147889054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 02 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 6f ?? 00 00 0a 25 11 00 28 ?? 00 00 06 6f ?? 00 00 0a 11 01 16 11 01 8e 69 6f ?? 00 00 0a 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANH_2147889066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANH!MTB"
        threat_id = "2147889066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 25 17 6f ?? 00 00 0a 00 25 18 6f ?? 00 00 0a 00 25 07 6f ?? 00 00 0a 00 13 08 11 08 6f ?? 00 00 0a 13 09 11 09 09 16 09 8e 69 28 ?? 00 00 06 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANI_2147889067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANI!MTB"
        threat_id = "2147889067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 02 7e ?? 00 00 04 28 ?? 01 00 06 25 17 7e ?? 00 00 04 28 ?? 01 00 06 25 18 7e ?? 00 00 04 28 ?? 01 00 06 25 11 04 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 11 01 16 11 01 8e 69 7e ?? 00 00 04 28 ?? 01 00 06 13 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANJ_2147889105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANJ!MTB"
        threat_id = "2147889105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 04 7e ?? 00 00 04 28 ?? 01 00 06 25 17 7e ?? 00 00 04 28 ?? 01 00 06 25 18 7e ?? 00 00 04 28 ?? 01 00 06 25 11 00 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 11 01 16 11 01 8e 69 7e ?? 00 00 04 28 ?? 01 00 06 13 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANK_2147889106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANK!MTB"
        threat_id = "2147889106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 08 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 28 ?? 00 00 06 25 06 28 ?? 00 00 06 28 ?? 00 00 06 07 16 07 8e 69 6f ?? 00 00 0a 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AANM_2147889112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AANM!MTB"
        threat_id = "2147889112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 11 02 7e ?? 00 00 04 28 ?? 01 00 06 25 17 7e ?? 00 00 04 28 ?? 01 00 06 25 18 7e ?? 00 00 04 28 ?? 01 00 06 25 11 00 7e ?? 00 00 04 28 ?? 01 00 06 7e ?? 00 00 04 28 ?? 01 00 06 11 01 16 11 01 8e 69 7e ?? 00 00 04 28 ?? 01 00 06 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NVDI_2147889497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NVDI!MTB"
        threat_id = "2147889497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 5c 00 00 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 20 ?? ?? ?? 12 20 ?? ?? ?? 12 61 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 20 ?? ?? ?? 8d 66 20 ?? ?? ?? 72 61 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 14 14 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 0a 20 ?? ?? ?? 87 20 ?? ?? ?? 87 61 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a a2 25 17 7e ?? ?? ?? 04 a2 25 18 17 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "PortScanner.Properties.Resources" ascii //weight: 1
        $x_1_3 = "pomrert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NDA_2147889499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NDA!MTB"
        threat_id = "2147889499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 03 a2 25 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0c 17 28}  //weight: 5, accuracy: Low
        $x_1_2 = "Es.Resources.resources" ascii //weight: 1
        $x_1_3 = "WindowsApp1.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AAQT_2147892064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AAQT!MTB"
        threat_id = "2147892064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NAV_2147892285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NAV!MTB"
        threat_id = "2147892285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 42 00 00 0a fe ?? ?? 00 fe ?? ?? 00 28 ?? ?? ?? 0a 25 26 fe ?? ?? 00 28 ?? ?? ?? 0a 25 26 fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 8e 69 6f ?? ?? ?? 0a 25 26 fe ?? ?? 00 28 ?? ?? ?? 0a 25 26 fe ?? ?? 00 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {fe 0c 00 00 fe 0c 01 00 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 25 26 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 25 26 fe ?? ?? 00 fe ?? ?? 00 28 ?? ?? ?? 0a 25 26 fe ?? ?? 00 fe ?? ?? 00 28 ?? ?? ?? 0a fe ?? ?? 00 fe ?? ?? 00 dd ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_3 = "ShibaWex Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSZF_2147893352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSZF!MTB"
        threat_id = "2147893352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 d7 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 18 16 8d 57 00 00 01 6f 71 04 00 06 20 f1 08 00 00 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AATR_2147893658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AATR!MTB"
        threat_id = "2147893658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 06 16 6f ?? 01 00 0a 13 07 12 07 28 ?? 01 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 06 17 58 0a 06 09 6f ?? 01 00 0a 32 d7 11 04 6f ?? 01 00 0a 13 06 de 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTAL_2147894739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTAL!MTB"
        threat_id = "2147894739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 38 a5 ff ff ff 11 02 28 ?? 00 00 0a 04 6f 98 00 00 0a 6f 99 00 00 0a 13 01 38 71 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTAO_2147895028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTAO!MTB"
        threat_id = "2147895028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 20 a0 00 00 00 28 ?? 00 00 06 28 ?? 00 00 06 20 04 00 00 00 38 a5 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTAV_2147895341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTAV!MTB"
        threat_id = "2147895341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 77 00 00 70 0a 72 85 00 00 70 0b 28 ?? 00 00 0a 6f 11 00 00 0a 28 ?? 00 00 0a 0c 08 06 6f 13 00 00 0a 2c 1a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTAX_2147895342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTAX!MTB"
        threat_id = "2147895342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 22 00 00 0a 6f 23 00 00 0a 13 35 11 35 73 0b 00 00 06 80 03 00 00 04 7e 03 00 00 04 6f 0d 00 00 06 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTBO_2147895889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTBO!MTB"
        threat_id = "2147895889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 17 0a 72 01 00 00 70 0b 73 14 00 00 0a 07 28 ?? 00 00 0a 0c 08 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTAW_2147897058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTAW!MTB"
        threat_id = "2147897058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 31 00 00 0a 72 06 03 00 70 6f 4a 00 00 0a 73 47 00 00 0a 25 6f 41 00 00 0a 16 6a 6f 42 00 00 0a 25 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSQM_2147897150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSQM!MTB"
        threat_id = "2147897150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 17 28 27 00 00 0a 00 00 28 12 00 00 06 6f 28 00 00 0a 26 28 11 00 00 06 6f 28 00 00 0a 26 00 de 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PSLQ_2147897585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PSLQ!MTB"
        threat_id = "2147897585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 05 00 00 06 28 07 00 00 06 74 04 00 00 01 28 06 00 00 06 74 01 00 00 1b 28 03 00 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTHL_2147901856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTHL!MTB"
        threat_id = "2147901856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 fe 00 00 0a 28 ?? 00 00 0a 04 28 ?? 03 00 06 28 ?? 03 00 06 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PTJL_2147903832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PTJL!MTB"
        threat_id = "2147903832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 07 00 00 06 38 9f 00 00 00 28 ?? 00 00 06 72 5c 01 00 70 28 ?? 00 00 0a 6f 24 00 00 0a 28 ?? 00 00 06 13 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RPX_2147906405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RPX!MTB"
        threat_id = "2147906405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 11 11 13 11 13 07 58 9e 11 13 17 58 13 13 11 13 11 11 8e 69 32 e9 11 0f 17 58 13 0f 11 0f 03 8e 69 3f 5a ff ff ff 11 0e 17 58 13 0e 11 0e 17 3f 44 ff ff ff 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RPX_2147906405_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RPX!MTB"
        threat_id = "2147906405"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 11 11 13 11 13 07 58 9e 11 13 17 58 13 13 11 13 11 11 8e 69 3f e6 ff ff ff 11 0f 17 58 13 0f 11 0f 03 8e 69 3f 48 ff ff ff 11 0e 17 58 13 0e 11 0e 17 3f 32 ff ff ff 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_KAD_2147907584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.KAD!MTB"
        threat_id = "2147907584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 20 00 01 00 00 5d [0-30] 61 d2 52}  //weight: 1, accuracy: Low
        $x_1_2 = "MSG_NET" ascii //weight: 1
        $x_1_3 = "Angelo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RP_2147915183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RP!MTB"
        threat_id = "2147915183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MAK5ID7H6SF8ADGGHJFKILOO" ascii //weight: 10
        $x_10_2 = "PAISDJSF8374JSKFHG5JGFL9SM" ascii //weight: 10
        $x_1_3 = "$$method0x6000316-1" ascii //weight: 1
        $x_1_4 = "$$method0x600032e-1" ascii //weight: 1
        $x_1_5 = "$$method0x600032e-2" ascii //weight: 1
        $x_1_6 = "$$method0x600033c-1" ascii //weight: 1
        $x_1_7 = "$$method0x600033c-2" ascii //weight: 1
        $x_1_8 = "$$method0x600034f-1" ascii //weight: 1
        $x_1_9 = "$$method0x600038e-1" ascii //weight: 1
        $x_1_10 = "$$method0x60005ab-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_OBS_2147917697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.OBS!MTB"
        threat_id = "2147917697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 06 00 20 05 00 00 00 fe 0c 08 00 9c 20 54 00 00 00 38 10 e5 ff ff 11 27 11 03 19 58 e0 91 1f 18 62 11 27 11 03 18 58 e0 91 1f 10 62 60 11 27 11 03 17 58 e0 91 1e 62 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PAFI_2147918297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PAFI!MTB"
        threat_id = "2147918297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 09 06 08 06 09 91 9c 06 09 11 09 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 0a 02 11 08 8f 1d 00 00 01 25 71 1d 00 00 01 06 11 0a 91 61 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_NC_2147918578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.NC!MTB"
        threat_id = "2147918578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58}  //weight: 3, accuracy: High
        $x_2_2 = "13eaff9e-4eba-4e0b-aa0b-f5aa3e330281" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AVD_2147918731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AVD!MTB"
        threat_id = "2147918731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 34 12 1f 28 ?? 00 00 0a 12 34 28 ?? 00 00 0a 26 16 13 35 12 28 28 ?? 00 00 0a 28 ?? 00 00 0a 13 35 03 11 34 91 13 36 06 11 35 91 13 37 11 36 11 37 61 d2 13 36 03 11 34 11 36 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AVD_2147918731_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AVD!MTB"
        threat_id = "2147918731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RDPCreator\\obj\\Release\\RDPCreator.pdb" ascii //weight: 2
        $x_5_2 = "http://147.45.44.104" ascii //weight: 5
        $x_3_3 = "CurrentVersion\\Policies\\System\" /v \"AllowRemoteRPC\" /t REG_DWORD /d 1 /f" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AVD_2147918731_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AVD!MTB"
        threat_id = "2147918731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TAZRJSZMYHHADNVWNOMASQJOGTEXGEFCT" ascii //weight: 1
        $x_1_2 = "TUWEYKHLPDTFBSTHVXUJESNLBVXIKWKYJBMAINVKOA" ascii //weight: 1
        $x_1_3 = "USNMPXQVPYGGWPFNFODINAEHIMVNBQVNZBWWTPXMTQSNPCLZDPTQBLGUOGEDCDTYDT" ascii //weight: 1
        $x_1_4 = "UGARLOLYMRDXOSMNESOVOYBEZJYRRPSQDSGQGANCNISFCZLWTIEQBTBVFWR" ascii //weight: 1
        $x_1_5 = "MXRFMZZUIXCBVRFIIGTZJMWXVJYNXHWMCCKMUKZHOKGINWLWOYYDWELABUKCBMWABPYT" ascii //weight: 1
        $x_1_6 = "KACWSCOGIZLEIQTUFAODULXDBZHROGWFGYLQMHSAEXNPHBKDJLZKSVXYCYUSVXR" ascii //weight: 1
        $x_1_7 = "ULSWOSRQWJPPGRJPUWEIMYHXOLNOOHIZJEVITLTZAWZKHZZJQQNM" ascii //weight: 1
        $x_1_8 = "RAVDUHDECCOBPGCWBVJCFIQYXPPLDYYTVQSEZEYDQUYU" ascii //weight: 1
        $x_1_9 = "KZUUQRETFYQRXYYTZMJRIWCKTZETLFDUZDUMPPGWKDRQZSGQMTIHTGKOWKBQMKHZV" ascii //weight: 1
        $x_1_10 = "AFYCMGYXDEISOPUYSZNNACNSQMGEPFBHWWJMQLGOEOGQXGOTHHJPE" ascii //weight: 1
        $x_1_11 = "AFHFLMBDAYGDBCEWAZTCUDRPOUQRNKRPTLHIRRNVUXPFBZFIJNA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_KAF_2147920176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.KAF!MTB"
        threat_id = "2147920176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 1c 91 61 d2 81 ?? 00 00 01 11 13 17 58 13 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_DKQ_2147920648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.DKQ!MTB"
        threat_id = "2147920648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5a 6d 13 16 11 16 6e 11 1a 6a 61 69 13 18 11 19 6e 11 1a 6a 61 69 13 1a 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91}  //weight: 2, accuracy: High
        $x_3_2 = {20 00 01 00 00 5d 13 1c 7e 03 00 00 04 16 11 13 6f ?? 00 00 0a 7e 03 00 00 04 17 11 1c 6f ?? 00 00 0a 03 7e 03 00 00 04 16 6f 19 00 00 0a 28 ?? 00 00 0a 8f 16 00 00 01 25 71 16 00 00 01 06 7e 03 00 00 04 17 6f 19 00 00 0a 28 ?? 00 00 0a 91 61 d2 81 16 00 00 01 11 13 17 58 13 13}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_WRA_2147920953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.WRA!MTB"
        threat_id = "2147920953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 1c 7e 03 00 00 04 11 1c 6f ?? ?? ?? ?? 7e 03 00 00 04 11 13 6f ?? ?? ?? ?? 03 7e 03 00 00 04 17 6f ?? ?? ?? ?? 8f 14 00 00 01 25 71 14 00 00 01 06 7e 03 00 00 04 16 6f 1a 00 00 0a 91 61 d2 81 14 00 00 01 28 1b 00 00 0a 7e 03 00 00 04 6f 1c 00 00 0a 11 13 17 58 13 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_DF_2147921597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.DF!MTB"
        threat_id = "2147921597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 32 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_ZMO_2147922136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.ZMO!MTB"
        threat_id = "2147922136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 69 13 26 08 17 58 20 ?? ?? ?? 00 5d 0c 09 06 08 91 58 20 ?? ?? ?? 00 5d 0d 06 08 91 13 27 06 08 06 09 91 9c 06 09 11 27 9c 06 08 91 06 09 91 58}  //weight: 5, accuracy: Low
        $x_4_2 = {13 35 03 11 34 91 13 36 06 11 35 91 13 ?? 11 36 11 37 61 d2 13 36 03 11 34 11 36 9c de 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AVI_2147927385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AVI!MTB"
        threat_id = "2147927385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 25 06 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 16 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 25 17 6f ?? ?? ?? 0a 00 0b 07 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AVI_2147927385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AVI!MTB"
        threat_id = "2147927385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Create persistent scheduled task" ascii //weight: 1
        $x_2_2 = "New-ScheduledTaskAction -Execute $tempPath -ErrorAction SilentlyContinue" ascii //weight: 2
        $x_3_3 = "New-ScheduledTaskTrigger -AtLogOn -ErrorAction SilentlyContinue" ascii //weight: 3
        $x_4_4 = "New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ErrorAction SilentlyContinue" ascii //weight: 4
        $x_5_5 = "New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Highest -ErrorAction SilentlyContinue" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_SWA_2147932323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.SWA!MTB"
        threat_id = "2147932323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 15 00 00 0a 6f 16 00 00 0a 6f 17 00 00 0a 0a 06 73 18 00 00 0a 25 17 6f 19 00 00 0a 00 25 72 01 00 00 70 6f 1a 00 00 0a 00 0b 00 07 28 1b 00 00 0a 26 00 de 05 26 00 00 de 00 16 28 1c 00 00 0a 00 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_AYA_2147932496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.AYA!MTB"
        threat_id = "2147932496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 23 00 00 00 00 00 00 00 00 0a 16 0b 2b 19 00 06 07 6c 23 00 00 00 00 00 00 00 40 28 4e 00 00 0a 58 0a 00 07 17 58 0b 07 20 40 42 0f 00 fe 04 0c 08 2d db 1f 64 28 28 00 00 0a 00 00 17 0d 2b bf}  //weight: 2, accuracy: High
        $x_1_2 = "NoProfile -ExecutionPolicy Bypass -Command" wide //weight: 1
        $x_1_3 = "IsRunAsAdmin" ascii //weight: 1
        $x_1_4 = "RestartAsAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_RDJ_2147933845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.RDJ!MTB"
        threat_id = "2147933845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 28 63 00 00 0a 13 08 11 08 11 06 74 25 00 00 01 73 3f 00 00 0a 0d 18 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_EABF_2147934431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.EABF!MTB"
        threat_id = "2147934431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b 12 03 08 02 03 08 91 08 04 28 d7 00 00 06 9c 08 17 d6 0c 08 07 31 ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_PLIJH_2147937032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.PLIJH!MTB"
        threat_id = "2147937032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 1f 09 0b 05 04 07 5d 9a 28 ?? 00 00 0a 03 28 ?? 00 00 06 28 ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_SLDE_2147942189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.SLDE!MTB"
        threat_id = "2147942189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {18 28 36 04 00 06 fe 0e 7a 02 fe 0c 7a 02 16 12 05 28 0a 00 00 0a 25 26 a2 fe 0c 7a 02 17 12 06 28 0c 00 00 0a 25 26 a2 fe 0c 7a 02 13 07 72 5b 00 00 70 11 07 28 0b 00 00 0a 25 26 26 72 9e 21 04 70 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vidar_ACH_2147944104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vidar.ACH!MTB"
        threat_id = "2147944104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 11 04 11 00 11 04 91 11 01 11 04 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

