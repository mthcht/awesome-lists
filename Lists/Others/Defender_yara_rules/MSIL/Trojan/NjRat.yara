rule Trojan_MSIL_NjRat_S_2147744373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.S!MTB"
        threat_id = "2147744373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 00 1a 28 05 00 (6f|28) ?? ?? 00 (0a|06|2b) ?? ?? ?? ?? ?? ?? ?? ?? 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_A_2147749271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.A"
        threat_id = "2147749271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "165d6ed988ac1dbec1627a1ca9899d84" wide //weight: 1
        $x_1_2 = "margorpdewolla eteled llawerif hsten" wide //weight: 1
        $x_1_3 = "led & 2 n- 0 gnip c/ exe.dmc" wide //weight: 1
        $x_1_4 = "nuR\\\\noisreVtnerruC\\\\swodniW\\\\tfosorciM\\\\erawtfoS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AA_2147753236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AA!MTB"
        threat_id = "2147753236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "conhost" ascii //weight: 1
        $x_1_2 = "Microsofrt" ascii //weight: 1
        $x_1_3 = "Widnows processees" ascii //weight: 1
        $x_1_4 = "DebuggerStepThroughAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NED_2147829572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NED!MTB"
        threat_id = "2147829572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 11 11 07 7b ?? 00 00 04 11 11 1e d8 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 11 11 17 d6 13 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEE_2147829894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEE!MTB"
        threat_id = "2147829894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SFU4mbT3GMret7THonf" ascii //weight: 3
        $x_3_2 = "rE4lpnT863QnijKQK5" ascii //weight: 3
        $x_3_3 = "Kh2o8BSHbd" ascii //weight: 3
        $x_2_4 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 2
        $x_2_5 = "91303.0.4v" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEJ_2147830482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEJ!MTB"
        threat_id = "2147830482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 06 73 14 00 00 0a 72 19 00 00 70 28 15 00 00 0a 28 02 00 00 06 28 16 00 00 0a 6f 17 00 00 0a 28 18 00 00 0a 00 06 28 19 00 00 0a 26 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEH_2147830643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEH!MTB"
        threat_id = "2147830643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e b7 11 04 16 9a 6f 39 00 00 0a 04 6f 39 00 00 0a d6 da 6f 49 00 00 0a 06 08 6f 4a 00 00 0a 6f 4b 00 00 0a 06 09 6f 4a 00 00 0a 6f 4b 00 00 0a 08}  //weight: 1, accuracy: High
        $x_1_2 = "5cd8f17f4086744065eb0992a09e05a2" wide //weight: 1
        $x_1_3 = "SGFjS2Vk" wide //weight: 1
        $x_1_4 = "Trojan.exe" wide //weight: 1
        $x_1_5 = "netsh firewall add" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEK_2147830933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEK!MTB"
        threat_id = "2147830933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$e38abd5e-051c-4b6b-b829-16d9e3c1da1d" ascii //weight: 1
        $x_1_2 = "eCDAcedav" ascii //weight: 1
        $x_1_3 = "eYMkq6Rsxj" ascii //weight: 1
        $x_1_4 = "eTUkpCMY8T" ascii //weight: 1
        $x_1_5 = "mkLdf8923rwE89zRgl4s" ascii //weight: 1
        $x_1_6 = "e5tW25j68" ascii //weight: 1
        $x_1_7 = "eN5zhKZKd" ascii //weight: 1
        $x_1_8 = "emBsxRLWq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEM_2147831358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEM!MTB"
        threat_id = "2147831358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$e38abd5e-051c-4b6b-b829-16d9e3c1da1d" ascii //weight: 5
        $x_5_2 = "sesteim.exe" ascii //weight: 5
        $x_3_3 = "add_Shutdown" ascii //weight: 3
        $x_2_4 = "v4.0.30319" ascii //weight: 2
        $x_1_5 = "wwwwwx" ascii //weight: 1
        $x_1_6 = "SSSSn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEO_2147831457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEO!MTB"
        threat_id = "2147831457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 06 72 f0 00 00 70 72 b5 01 00 70 6f 10 00 00 0a 00 72 b5 01 00 70 28 11 00 00 0a 26 00 de 0b}  //weight: 1, accuracy: High
        $x_1_2 = "9dbb93d14e7d880f.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEP_2147831459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEP!MTB"
        threat_id = "2147831459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide //weight: 5
        $x_5_2 = "SELECT * FROM AntivirusProduct" wide //weight: 5
        $x_5_3 = "C:\\Program Files\\Coinomi\\Wallet" wide //weight: 5
        $x_4_4 = "Exodus_" wide //weight: 4
        $x_4_5 = "Meta_Firefx_" wide //weight: 4
        $x_3_6 = "get_ServicePack" ascii //weight: 3
        $x_3_7 = "Shell" ascii //weight: 3
        $x_3_8 = "Keylogger" ascii //weight: 3
        $x_2_9 = "GetProcessById" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEQ_2147831462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEQ!MTB"
        threat_id = "2147831462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CCHEKLJBLDBMN" ascii //weight: 5
        $x_5_2 = "GMIOFLIEKPEKE" ascii //weight: 5
        $x_5_3 = "SFU4mbT3GMre" ascii //weight: 5
        $x_4_4 = "fieldimpl3" ascii //weight: 4
        $x_4_5 = "get_MachineName" ascii //weight: 4
        $x_1_6 = "Shell" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_9 = "GetProcessesByName" ascii //weight: 1
        $x_1_10 = "OpenProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NES_2147832048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NES!MTB"
        threat_id = "2147832048"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 3e 00 00 04 ?? ?? ?? 01 00 00 59 97 29 19 00 00 11 02 50 6f 8b 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_4_2 = "Discord" ascii //weight: 4
        $x_4_3 = "NtSetInformationProcess" ascii //weight: 4
        $x_4_4 = "set_MinWorkingSet" ascii //weight: 4
        $x_4_5 = "set_UseShellExecute" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NET_2147832049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NET!MTB"
        threat_id = "2147832049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 09 28 6d 00 00 0a 0a 08 06 16 06 8e b7 6f 6e 00 00 0a 08 6f 6f 00 00 0a 28 70 00 00 0a 11 04 6f 71 00 00 0a 6f 72 00 00 0a 13 09 de 11}  //weight: 5, accuracy: High
        $x_2_2 = "<Inmate>" wide //weight: 2
        $x_2_3 = "image.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEV_2147832167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEV!MTB"
        threat_id = "2147832167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 38 00 00 0a 14 18 8d 17 00 00 01 25 16 11 04 72 ?? 01 00 70 28 33 00 00 0a a2 25 17 09 28 35 00 00 0a a2 6f 39 00 00 0a 26 de 0f}  //weight: 5, accuracy: Low
        $x_2_2 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 2
        $x_1_3 = "91303.0.4v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEW_2147832168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEW!MTB"
        threat_id = "2147832168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {11 0d 28 2c 00 00 0a 13 0f 1f 12 38 7f fd ff ff 11 04 7b 09 00 00 04 11 08 1e d6 11 0f 1a 12 01 28 16 00 00 06 2d 06}  //weight: 7, accuracy: High
        $x_1_2 = "CreateProcess" ascii //weight: 1
        $x_1_3 = "GetThreadContext" ascii //weight: 1
        $x_1_4 = "ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "VirtualAllocEx" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
        $x_1_8 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEX_2147832379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEX!MTB"
        threat_id = "2147832379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 01 13 04 11 04 2d dc 28 ?? 00 00 0a 07 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 01 00 70}  //weight: 5, accuracy: Low
        $x_3_2 = "Invoke" wide //weight: 3
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEY_2147832381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEY!MTB"
        threat_id = "2147832381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\5cd8f17f4086744065eb0992a09e05a2" wide //weight: 5
        $x_5_2 = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide //weight: 5
        $x_5_3 = "SGFjS2Vk" wide //weight: 5
        $x_3_4 = "netsh firewall add allowedprogram" wide //weight: 3
        $x_3_5 = "UseShellExecute" wide //weight: 3
        $x_3_6 = "CreateNoWindow" wide //weight: 3
        $x_3_7 = "cmd.exe" wide //weight: 3
        $x_3_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEZ_2147832822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEZ!MTB"
        threat_id = "2147832822"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 08 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 08 17 58 0c 08 06 8e 69 17 59 fe 02 16 fe 01 13 07 11 07 2d dc}  //weight: 5, accuracy: Low
        $x_5_2 = {07 28 09 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0d 09}  //weight: 5, accuracy: Low
        $x_2_3 = "Load" wide //weight: 2
        $x_2_4 = "Invoke" wide //weight: 2
        $x_2_5 = "entrypoint" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAB_2147833501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAB!MTB"
        threat_id = "2147833501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {09 08 9a 0b 06 07 18 28 77 00 00 0a 28 78 00 00 0a 28 79 00 00 0a 28 75 00 00 0a 0a 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d d3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAC_2147833504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAC!MTB"
        threat_id = "2147833504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 9a 0d 06 09 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 08 17 d6 0c 08 07 8e 69 fe 04 13 04 11 04 2d d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ABAI_2147833555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ABAI!MTB"
        threat_id = "2147833555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {13 04 11 04 09 17 73 ?? ?? ?? 0a 13 05 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 5b 06 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 58 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 14 16 8d ?? ?? ?? 01 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 06 2a}  //weight: 6, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "Patrick_Crypter_Stub.Form1.resources" ascii //weight: 1
        $x_1_4 = "AfzdIHOfGi7323Sf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAD_2147834125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAD!MTB"
        threat_id = "2147834125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "673393b7-3349-44d8-9de0-002104354a7c" ascii //weight: 5
        $x_5_2 = "A. Pilet SA" ascii //weight: 5
        $x_5_3 = "Interrogation" ascii //weight: 5
        $x_5_4 = "Pilet.Spooler.Modbus" ascii //weight: 5
        $x_5_5 = "2.6.0.0" ascii //weight: 5
        $x_5_6 = "SELECT * FROM utilisateurs" wide //weight: 5
        $x_5_7 = "failed to transmit to connection id" wide //weight: 5
        $x_2_8 = "Fonction Modbus" wide //weight: 2
        $x_2_9 = "c:\\program files\\eau\\log" wide //weight: 2
        $x_2_10 = "set_SuppressKeyPress" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAE_2147834188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAE!MTB"
        threat_id = "2147834188"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 08 9a 0b 06 07 18 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAF_2147834399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAF!MTB"
        threat_id = "2147834399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 28 ?? 00 00 0a 02 06 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAG_2147834797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAG!MTB"
        threat_id = "2147834797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 50 28 30 00 00 0a 0a 12 00 28 0a 00 00 06}  //weight: 10, accuracy: High
        $x_10_2 = {0b 14 0c 16 0d 16 13 04 16 13 05 14 13 06 16 13 07 12 01 12 02 09 12 07 12 04 12 05 12 06 16 28 19 00 00 06 26 11 07}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAJ_2147835135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAJ!MTB"
        threat_id = "2147835135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$1f0b1d5d-53fe-466f-8ea1-1d515f5e7ddb" ascii //weight: 5
        $x_5_2 = "svchost.My" ascii //weight: 5
        $x_5_3 = "SmartAssembly.HouseOfCards" ascii //weight: 5
        $x_5_4 = "aspnet_wp.exe" wide //weight: 5
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAL_2147835141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAL!MTB"
        threat_id = "2147835141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {38 00 00 00 00 7e 1e 00 00 04 17 9a 28 45 00 00 0a 7e 20 00 00 04 28 37 00 00 06 28 45 00 00 0a 28 35 00 00 0a 80 1f 00 00 04 38}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAM_2147835612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAM!MTB"
        threat_id = "2147835612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 08 04 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 0d 06 09 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 08 17 d6 0c 08 11 04 13 05 11 05 31 c7}  //weight: 10, accuracy: Low
        $x_5_2 = "VigenereDecrypt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAN_2147835613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAN!MTB"
        threat_id = "2147835613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e cb 00 00 04 7e ca 00 00 04 7e c6 00 00 04 28 ?? 00 00 06 7e 29 00 00 04 08 07 28 ?? 00 00 06 28 ?? 00 00 06 13 04 7e cc 00 00 04 7e ca 00 00 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAO_2147835618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAO!MTB"
        threat_id = "2147835618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 4a 00 00 0a 0b 72 ?? ?? 00 70 07 73 ?? 00 00 0a 0c 08 02 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 06 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "DetectVirtualMachine" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAP_2147835620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAP!MTB"
        threat_id = "2147835620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 09 11 09 16 11 04 a2 00 11 09 17 11 05 08 17 28 ?? 00 00 0a a2 00 11 09 18 11 06 08 17 28 ?? 00 00 0a a2 00 11 09 19 11 07 08 17 28 ?? 00 00 0a a2 00 11 09 1a 11 08 08 17 28 ?? 00 00 0a a2 00 11 09 28 ?? 00 00 0a 13 04 08 17 d6 0c 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAT_2147836975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAT!MTB"
        threat_id = "2147836975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0c 07 08 7e 06 00 00 04 6f 20 00 00 0a 28 21 00 00 0a de 0a 08 2c 06 08 6f 22 00 00 0a dc 07}  //weight: 10, accuracy: High
        $x_5_2 = "latin-e.com" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAU_2147836979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAU!MTB"
        threat_id = "2147836979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 16 0b 38 21 00 00 00 7e 2f 00 00 04 07 9a 06 28 b2 00 00 0a 39 0b 00 00 00 7e 30 00 00 04 74 2e 00 00 01 2a 07 17 58 0b 07}  //weight: 10, accuracy: High
        $x_5_2 = "MWgawDcWcagTvVmsg7H" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAV_2147837430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAV!MTB"
        threat_id = "2147837430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$5d818571-dc9d-4b19-a8b8-a3edf57df1f6" ascii //weight: 10
        $x_5_2 = "CONTER FILM.exe" ascii //weight: 5
        $x_1_3 = "System.Windows.Forms.DataVisualization.Charting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAZ_2147837965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAZ!MTB"
        threat_id = "2147837965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$7cb45faf-7e0f-4b79-83ee-e63157656948" ascii //weight: 5
        $x_5_2 = "c:\\users\\teo\\documents\\visual studio 2015\\Projects\\rosinject\\rosinject\\obj\\Debug\\rosinject.pdb" ascii //weight: 5
        $x_5_3 = "rosinject.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBA_2147838031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBA!MTB"
        threat_id = "2147838031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "85ea163a-a047-4dca-a58b-1d8a25b53772" ascii //weight: 2
        $x_2_2 = "SpyNote 7.0 hacking" wide //weight: 2
        $x_2_3 = "[ Android RAT ]" wide //weight: 2
        $x_2_4 = "D H O U I B I" wide //weight: 2
        $x_2_5 = "keylogger" ascii //weight: 2
        $x_2_6 = "content://sms/inbox" wide //weight: 2
        $x_2_7 = "C:\\Windows\\System32\\mmc.exe" wide //weight: 2
        $x_2_8 = "Resources\\Imports\\Payload" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBC_2147838271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBC!MTB"
        threat_id = "2147838271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 07 16 1a 28 ?? 00 00 06 26 07 16 28 ?? 00 00 06 0c 06 16 73 ?? 00 00 0a 0d 08 8d 26 00 00 01 13 04}  //weight: 5, accuracy: Low
        $x_5_2 = {46 00 00 00 26 20 02 00 00 00 38 1d 00 00 00 09 11 04 16 08 28 ?? 00 00 06 26}  //weight: 5, accuracy: Low
        $x_2_3 = "Decompress" ascii //weight: 2
        $x_2_4 = "RPF:SmartAssembly" ascii //weight: 2
        $x_2_5 = "System.Windows.Forms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBF_2147838390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBF!MTB"
        threat_id = "2147838390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "178a8c43-93a6-4eb7-a2fc-84303966b50e" ascii //weight: 3
        $x_3_2 = "RoboCop.exe" ascii //weight: 3
        $x_3_3 = "RoboCop.My" ascii //weight: 3
        $x_1_4 = "B.rsrc" ascii //weight: 1
        $x_1_5 = "get_Evidence" ascii //weight: 1
        $x_1_6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBJ_2147838736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBJ!MTB"
        threat_id = "2147838736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 0d 11 0d 11 0c 6f 25 00 00 0a 16 13 0e 2b 21 11 09 11 0e 8f 06 00 00 01 25 71 06 00 00 01 11 0c 11 0e 91 61 d2 81 06 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9}  //weight: 10, accuracy: High
        $x_5_2 = "WindowsFormsApplication1.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBH_2147838958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBH!MTB"
        threat_id = "2147838958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 07 14 fe 01 16 fe 01 0d 09 39 14 00 00 00 02 03 04 07 28 30 00 00 06 0a 38 34 00 00 00 38 26 00 00 00 00 05 75 35 00 00 01 0c 08 14 fe 01 16 fe 01 0d 09}  //weight: 10, accuracy: High
        $x_2_2 = "This assembly is protected" wide //weight: 2
        $x_2_3 = "IntelliLock" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBL_2147838959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBL!MTB"
        threat_id = "2147838959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 04 11 04 13 05 06 1a 58 16 54 06 1e 58 11 05 06 1a 58 28 52 00 00 06 54 7e d7 00 00 04 06 1e 58 4a 28 55 00 00 06 28 d9 00 00 06 13 06}  //weight: 10, accuracy: High
        $x_2_2 = "Stub.exe" ascii //weight: 2
        $x_2_3 = "Powered by SmartAssembly 8.0.2.4779" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBK_2147839076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBK!MTB"
        threat_id = "2147839076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 05 08 17 28 ?? 00 00 0a 11 06 08 17 28 ?? 00 00 0a 11 07 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 09 11 09 2d ca 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a}  //weight: 10, accuracy: Low
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBM_2147839126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBM!MTB"
        threat_id = "2147839126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7e 0e 00 00 04 28 0c 00 00 06 28 62 00 00 0a 0a 28 63 00 00 0a 06 6f 64 00 00 0a 0b 07 6f 65 00 00 0a 0c 08 14 14 6f 61 00 00 0a 26 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AFF_2147839138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AFF!MTB"
        threat_id = "2147839138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 05 50 6f ?? ?? ?? 0a 26 07 0e 04 6f ?? ?? ?? 0a 26 07 0e 05 6f ?? ?? ?? 0a 26 07 0e 06 8c}  //weight: 2, accuracy: Low
        $x_1_2 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_3 = "shell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBN_2147839464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBN!MTB"
        threat_id = "2147839464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 26 0c 07 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 0e 04 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 25 26 03 16 03}  //weight: 10, accuracy: Low
        $x_5_2 = "dfgsgsf563653.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBP_2147839720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBP!MTB"
        threat_id = "2147839720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 16 0c 08 b5 12 01 1f 64 14 13 04 12 04 1f 64 28 2c 00 00 06 2c 04 17 0a de 1a 08 17 d6 0c 08 1a 31 e0 de 0e}  //weight: 10, accuracy: High
        $x_2_2 = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBQ_2147839722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBQ!MTB"
        threat_id = "2147839722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7e 09 00 00 04 08 07 28 2b 00 00 0a 16 6f 2c 00 00 0a 13 05 12 05 28 2d 00 00 0a 6f 2e 00 00 0a 00 07 09 12 01 28 2f 00 00 0a 13 06 11 06 2d d0}  //weight: 10, accuracy: High
        $x_2_2 = "loadM" ascii //weight: 2
        $x_2_3 = "WindowsApp1" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBS_2147839741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBS!MTB"
        threat_id = "2147839741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "d10e4c9a-1885-4d49-8483-4214f5681a6b" ascii //weight: 5
        $x_5_2 = "dfgsgsf563653.pdb" ascii //weight: 5
        $x_5_3 = "ZGZnc2dzZjU2MzY1MyU=" wide //weight: 5
        $x_3_4 = "CryptoObfuscator_Output" ascii //weight: 3
        $x_1_5 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBR_2147839965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBR!MTB"
        threat_id = "2147839965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 1b 00 00 06 0b 07 6f 32 00 00 0a 17 da 0c 16 0d 2b 1f 7e 0a 00 00 04 07 09 16 6f 33 00 00 0a 13 04 12 04 28 34 00 00 0a 6f 35 00 00 0a 09 17 d6 0d 09 08 31 dd}  //weight: 10, accuracy: High
        $x_5_2 = "WindowsApp1.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBT_2147840112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBT!MTB"
        threat_id = "2147840112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7 7e ?? 00 00 04 0c 2b 00 08 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "cdn.discordapp.com/attachments" wide //weight: 2
        $x_2_3 = "Form1_Load" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBW_2147840885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBW!MTB"
        threat_id = "2147840885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "db551d35-2a94-4775-8fc5-372f817c8695" ascii //weight: 5
        $x_5_2 = "Linko.exe" ascii //weight: 5
        $x_1_3 = "Powered by SmartAssembly 6.7.0.239" ascii //weight: 1
        $x_1_4 = "HtpL File" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBX_2147840889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBX!MTB"
        threat_id = "2147840889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 77 28 1a 00 00 06 28 31 00 00 0a 28 32 00 00 0a 13 71 11 71 6f 33 00 00 0a 0a 14 13 79 14 13 76 06 6f 34 00 00 0a 8e b7 16 fe 02 13 7e 11 7e 2c 25}  //weight: 10, accuracy: High
        $x_2_2 = "DebuggerHiddenAttribute" ascii //weight: 2
        $x_2_3 = "Windows.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBZ_2147840981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBZ!MTB"
        threat_id = "2147840981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f8e8e79c-3624-4a23-96ce-2b5d52caf6ff" ascii //weight: 5
        $x_5_2 = "newenc.exe" ascii //weight: 5
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Form1_Load" ascii //weight: 1
        $x_1_5 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBY_2147841111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBY!MTB"
        threat_id = "2147841111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 93 00 00 0a 02 11 54 28 94 00 00 0a 20 14 38 01 00 28 4d 00 00 06 18 18 6f 3e 00 00 06 6f 95 00 00 0a 0c 08 14}  //weight: 10, accuracy: High
        $x_5_2 = "RPF:SmartAssembly" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECB_2147841112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECB!MTB"
        threat_id = "2147841112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 59 00 00 0a 11 68 28 5a 00 00 0a 6f 5b 00 00 0a 0a 06 14 72 7b 24 01 70 16 8d 03 00 00 01 14 14 14 28 5c 00 00 0a 14}  //weight: 10, accuracy: High
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
        $x_1_4 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECD_2147841313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECD!MTB"
        threat_id = "2147841313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {7e d9 02 00 04 07 09 16 6f 58 00 00 0a 13 04 12 04 28 59 00 00 0a 6f 5a 00 00 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 10, accuracy: High
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECE_2147841431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECE!MTB"
        threat_id = "2147841431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "8a19955f-721a-4111-9a7a-426f4cbddfb6" ascii //weight: 5
        $x_2_2 = "social media optimization.exe" ascii //weight: 2
        $x_2_3 = "Evaluation Version" wide //weight: 2
        $x_1_4 = "System.Reflection" ascii //weight: 1
        $x_1_5 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECF_2147841432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECF!MTB"
        threat_id = "2147841432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "93ddf7df-7c7f-4cd3-8af5-d8d25c2edd3e" ascii //weight: 5
        $x_2_2 = "Monela fashion.exe" ascii //weight: 2
        $x_2_3 = "Trial Expired" wide //weight: 2
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "System.Reflection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECG_2147841521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECG!MTB"
        threat_id = "2147841521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 09 6f 3b 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 02 8e b7 6f ?? 00 00 0a 0c}  //weight: 10, accuracy: Low
        $x_2_2 = "RPF:SmartAssembly" ascii //weight: 2
        $x_2_3 = "Shehada\\Desktop\\njSRC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECH_2147841612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECH!MTB"
        threat_id = "2147841612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 09 8e b7 32 0c 20 93 00 00 00 13 04 38 bb 53 ff ff 20 b7 00 00 00 2b f2 06 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "GetExecutingAssembly" ascii //weight: 2
        $x_2_3 = "CLASSEK_TEAM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECK_2147841614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECK!MTB"
        threat_id = "2147841614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "9959fd57-98b7-4083-90d1-36d641de2321" ascii //weight: 5
        $x_2_2 = "microoft.exe" ascii //weight: 2
        $x_2_3 = "microoft.My" ascii //weight: 2
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_CNB_2147841874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.CNB!MTB"
        threat_id = "2147841874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 20 ?? ?? ?? ?? 13 10 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECJ_2147841883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECJ!MTB"
        threat_id = "2147841883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f8dd38e2-f03f-4507-a946-7576b29734fc" ascii //weight: 5
        $x_2_2 = "aR3nbf8dQp2feLmk31.SplashForm.resources" ascii //weight: 2
        $x_2_3 = "Eziriz's \".NET Reactor" wide //weight: 2
        $x_1_4 = "RPF:SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECL_2147841884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECL!MTB"
        threat_id = "2147841884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 0d 00 00 0a 28 0e 00 00 0a d0 11 00 00 01 28 0f 00 00 0a 72 ?? 00 00 70 28 10 00 00 0a 0a 16 8c ?? 00 00 01 0b 17 8d ?? 00 00 01 0d 09 16}  //weight: 10, accuracy: Low
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_CNC_2147842010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.CNC!MTB"
        threat_id = "2147842010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 04 17 59 6f ?? ?? ?? ?? 16 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 6a 03 04 08 5d 8c ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6e 59 0b 06 07 d1 8c ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 00 11 04 17 58 13 04 11 04 09 fe 02 16 fe 01 13 07 11 07 2d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECO_2147842026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECO!MTB"
        threat_id = "2147842026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a2 00 11 0f 1f 0a 11 05 08 17 28 ?? 00 00 0a a2 00 11 0f 28 ?? 00 00 0a 13 0e 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 11 11 11 3a 44 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECM_2147842138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECM!MTB"
        threat_id = "2147842138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 96 00 00 0a 11 38 28 ?? 00 00 0a 6f ?? 00 00 0a 13 39 11 39 14 72 ?? e2 03 70 16 8d 05 00 00 01 14 14 14 28 99 00 00 0a 14 72 ?? e2 03 70 18 8d 05 00 00 01 13 3b 11 3b 16 14 a2 00 11 3b 17 14 a2 00 11 3b 14 14 14}  //weight: 10, accuracy: Low
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECN_2147842139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECN!MTB"
        threat_id = "2147842139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 11 04 06 6f ?? 00 00 0a 11 04 05 6f ?? 00 00 0a 11 04 0e 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 03 16 03 8e b7 6f ?? 00 00 0a 0b 11 04 6f ?? 00 00 0a 07 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "RPF:SmartAssembly" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "EntryPoint" wide //weight: 1
        $x_1_5 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECR_2147842213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECR!MTB"
        threat_id = "2147842213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 37 11 36 fe 02 16 fe 01 13 3c 11 3c 3a ?? fc ff ff 28 ?? 00 00 0a 11 38 28 ?? 00 00 0a 6f ?? 00 00 0a 13 39 11 39}  //weight: 10, accuracy: Low
        $x_2_2 = "HideModuleNameAttribute" ascii //weight: 2
        $x_2_3 = "__ENCAddToList" ascii //weight: 2
        $x_2_4 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECS_2147842552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECS!MTB"
        threat_id = "2147842552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 9d 00 00 0a 02 11 50 28 9e 00 00 0a 72 65 37 01 70 18 18 6f 3c 00 00 06 6f 9f 00 00 0a 13 54 11 54 14}  //weight: 10, accuracy: High
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
        $x_2_3 = "IntelliLock" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECT_2147842553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECT!MTB"
        threat_id = "2147842553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 70 28 07 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 26 de d3 07 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "Comments" wide //weight: 1
        $x_1_5 = "Invoker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECV_2147842554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECV!MTB"
        threat_id = "2147842554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GzRuler.Form1.resources" ascii //weight: 3
        $x_3_2 = "WajUSpRHC5GEN7B45r" ascii //weight: 3
        $x_2_3 = ".NET Reactor" wide //weight: 2
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "RSACryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECW_2147842565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECW!MTB"
        threat_id = "2147842565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$f1611ff6-25c2-479b-88aa-cb5a8a95f118" ascii //weight: 5
        $x_3_2 = "_007Stub.Properties" ascii //weight: 3
        $x_3_3 = "PvroikJllY" ascii //weight: 3
        $x_1_4 = "GetProcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECY_2147842640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECY!MTB"
        threat_id = "2147842640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 2d 00 00 01 25 d0 5c 03 00 04 28 5c 00 00 0a 6f 86 00 00 0a 06 07 6f 8a 00 00 0a 17}  //weight: 10, accuracy: High
        $x_2_2 = "q3oMVe54wE47w4v68C7s2I" ascii //weight: 2
        $x_2_3 = "WriteProcessMemory" ascii //weight: 2
        $x_2_4 = "Invoke" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECX_2147843076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECX!MTB"
        threat_id = "2147843076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 05 17 9a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 10, accuracy: Low
        $x_2_2 = "WOLFDECRYPT" ascii //weight: 2
        $x_2_3 = "NoIsGood" ascii //weight: 2
        $x_2_4 = "FuckYou" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECZ_2147843078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECZ!MTB"
        threat_id = "2147843078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 da 0c 16 0d 2b 20 7e ?? ?? 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 10, accuracy: Low
        $x_2_2 = "GetPixel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDC_2147843105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDC!MTB"
        threat_id = "2147843105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$d4d791f1-71e5-458d-918a-98eac9468641" ascii //weight: 5
        $x_4_2 = "e-ticket for hm" wide //weight: 4
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDD_2147843107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDD!MTB"
        threat_id = "2147843107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f8060b6a-e3fa-4582-ad1f-78391d0baa77" ascii //weight: 5
        $x_2_2 = "XIII COMMUNITY" ascii //weight: 2
        $x_2_3 = "VigenereDecrypt" ascii //weight: 2
        $x_1_4 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDB_2147843183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDB!MTB"
        threat_id = "2147843183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 02 16 fe 01 13 08 11 08 3a c5 ff ff ff 28 52 00 00 0a 09 28 53 00 00 0a 6f 54 00 00 0a 13 06 11 06 14}  //weight: 10, accuracy: High
        $x_1_2 = "RPF:SmartAssembly" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDG_2147843185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDG!MTB"
        threat_id = "2147843185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$d535fd87-3b10-4f6f-bc62-d31dbc060a16" ascii //weight: 5
        $x_2_2 = "De2i5Sptiitp7tFY6M2" ascii //weight: 2
        $x_2_3 = "windowtime.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBU_2147843318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBU!MTB"
        threat_id = "2147843318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 0d 11 0d 11 0c 6f 21 00 00 0a 16 13 0e 2b 21 11 09 11 0e 8f 07 00 00 01 25 71 07 00 00 01 11 0c 11 0e 91 61 d2 81 07 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9}  //weight: 10, accuracy: High
        $x_5_2 = "TV qq Q A" wide //weight: 5
        $x_2_3 = "d7367634d3864d0f8ac3e6386b86511e" ascii //weight: 2
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEBV_2147843319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEBV!MTB"
        threat_id = "2147843319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 2b 1b 00 7e 36 00 00 04 06 7e 36 00 00 04 06 91 20 51 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 36 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 10, accuracy: High
        $x_5_2 = "s://cdn.dis" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECC_2147843321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECC!MTB"
        threat_id = "2147843321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 0f 11 0f 16 11 0e a2 00 11 0f 17 11 04 08 17 28 8f 00 00 0a a2 00 11 0f 18 11 06 08 17 28 8f 00 00 0a a2 00 11 0f 19 11 07 08 17}  //weight: 10, accuracy: High
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
        $x_1_4 = "Form1_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NECQ_2147843346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NECQ!MTB"
        threat_id = "2147843346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 00 06 0b 07 6f ?? 00 00 0a 17 da 0c 16 0d 2b 20 7e ?? 03 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 10, accuracy: Low
        $x_4_2 = "WinForms_RecursiveFormCreate" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ABLU_2147843439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ABLU!MTB"
        threat_id = "2147843439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c 02 0d 08 09 16 09 8e b7 6f ?? ?? ?? 0a 13 04 dd ?? ?? ?? 00 dd ?? ?? ?? 00 42 00 06 07 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDH_2147843442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDH!MTB"
        threat_id = "2147843442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3a cb ff ff ff 26 20 01 00 00 00 38 c0 ff ff ff 11 01 2a 11 01 11 02 18 5b 02 11 02 18 6f 09 00 00 0a 1f 10 28 0a 00 00 0a 9c 38 4d 00 00 00 16 13 02 38 ab ff ff ff 02 6f 0b 00 00 0a 13 03 38 0e 00 00 00 11 02 11 03}  //weight: 10, accuracy: High
        $x_5_2 = "<AuthPass Setup" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDI_2147843443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDI!MTB"
        threat_id = "2147843443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "5016571c-3639-49b4-b2d5-e8705fd95a11" ascii //weight: 5
        $x_2_2 = "CsAntiProcess" ascii //weight: 2
        $x_2_3 = "streamWebcam" ascii //weight: 2
        $x_2_4 = "GetAntiVirus" ascii //weight: 2
        $x_2_5 = "get_MachineName" ascii //weight: 2
        $x_2_6 = "get_Clipboard" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDE_2147843624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDE!MTB"
        threat_id = "2147843624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 1b 11 1b 3a ae fe ff ff 28 ?? 00 00 0a 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 07 14}  //weight: 10, accuracy: Low
        $x_5_2 = "hajza.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDJ_2147843626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDJ!MTB"
        threat_id = "2147843626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 0d 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 10 11 10 3a 53 ff ff ff 28 ?? 00 00 0a 11 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 14}  //weight: 10, accuracy: Low
        $x_2_2 = "EntryPoint" wide //weight: 2
        $x_2_3 = "Invoke" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDL_2147843864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDL!MTB"
        threat_id = "2147843864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 2b 53 06 07 9a 0c 08 6f ?? 00 00 0a 0d 16 13 04 2b 38 09 11 04 9a 13 05 11 05 6f ?? 00 00 0a 72 ?? 00 00 70 03 28 ?? 00 00 0a 6f ?? 00 00 0a 2c 13 08 6f ?? 00 00 0a 11 05}  //weight: 10, accuracy: Low
        $x_2_2 = "Client.exe" ascii //weight: 2
        $x_2_3 = "TllBTiBDQVQ=" wide //weight: 2
        $x_2_4 = "WScript.Shell" wide //weight: 2
        $x_2_5 = "notepad.lnk" wide //weight: 2
        $x_2_6 = "powershell.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDK_2147843929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDK!MTB"
        threat_id = "2147843929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 28 4b 00 00 0a 72 e6 25 01 70 18 18 28 29 00 00 06 0b 07 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 00 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "IntelliLock" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDN_2147843930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDN!MTB"
        threat_id = "2147843930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "61f56a94-c82d-4caa-839b-19752a41fe38" ascii //weight: 5
        $x_2_2 = "VIP Toolsassemblychange.exe" wide //weight: 2
        $x_2_3 = "_Encrypted$" wide //weight: 2
        $x_2_4 = "By FIGHTER" ascii //weight: 2
        $x_1_5 = "SmartAssembly.HouseOfCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDP_2147843932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDP!MTB"
        threat_id = "2147843932"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 8e 69 18 da 17 d6 8d ?? 00 00 01 0a 03 8e 69 17 da 0b 38 1b 00 00 00 06 07 17 da 02 03 07 91 03 07 17 da 91 65 b5 28 ?? 00 00 06 25 26 9c 07 15 d6 0b 07 17}  //weight: 10, accuracy: Low
        $x_2_2 = "PolyDeCrypt" ascii //weight: 2
        $x_2_3 = "PolyMorphicStairs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDQ_2147844057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDQ!MTB"
        threat_id = "2147844057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$3b9e6762-e2e4-4a36-9a4f-9c7e565cc37e" ascii //weight: 5
        $x_5_2 = "Obfuscated\\Obfuscated\\explorer.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDO_2147844167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDO!MTB"
        threat_id = "2147844167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "123ffc56-e123-1234-876d-1a3f123456e9" ascii //weight: 5
        $x_2_2 = "5555.55.3567.002" ascii //weight: 2
        $x_2_3 = "process.pdb" ascii //weight: 2
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDS_2147844430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDS!MTB"
        threat_id = "2147844430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "3a687b84-888d-4435-9feb-39d65e69884c" ascii //weight: 4
        $x_4_2 = "Obfuscated\\explorer.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDT_2147844431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDT!MTB"
        threat_id = "2147844431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ed652afe-0058-438a-a762-36d46d8c2e1c" ascii //weight: 5
        $x_2_2 = "RPF:SmartAssembly" ascii //weight: 2
        $x_2_3 = "kZZAIAO5YjoLRIAUdw" ascii //weight: 2
        $x_2_4 = "SharpZipLib" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDU_2147844432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDU!MTB"
        threat_id = "2147844432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d8 b7 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5 02 02 50 8e b7 17 da}  //weight: 10, accuracy: High
        $x_4_2 = "PolyDeCrypt" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDV_2147844546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDV!MTB"
        threat_id = "2147844546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "f5a7837f-9641-4af0-ba06-a3e68f75189d" ascii //weight: 5
        $x_2_2 = "0.exe" ascii //weight: 2
        $x_1_3 = "get_EntryPoint" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NJA_2147845306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NJA!MTB"
        threat_id = "2147845306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07}  //weight: 5, accuracy: High
        $x_1_2 = "mini calculator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NJA_2147845306_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NJA!MTB"
        threat_id = "2147845306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 0f 00 00 00 26 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 08 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 14 14 14 17 28 ?? ?? ?? 0a 26 dd ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsApp1.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_CSSI_2147846459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.CSSI!MTB"
        threat_id = "2147846459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 28 08 00 00 06 6f ?? ?? ?? ?? 0d 2b 15 12 03 28 24 00 00 0a 13 04 11 04 28 06 00 00 06 de 03 26 de 00 12 03 28 25 00 00 0a 2d e2}  //weight: 5, accuracy: Low
        $x_1_2 = "ThTduZeGbXHPIfNyBKKfiMfENIbTC" ascii //weight: 1
        $x_1_3 = "WZQRdrHcYoFcziWNgMvjHoHVWLPf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDR_2147847431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDR!MTB"
        threat_id = "2147847431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 0d 2b 39 02 09 28 ?? 00 00 0a 28 ?? 00 00 0a 6a 03 28 ?? 00 00 0a 04 07 5d 6c 58 28 ?? 00 00 0a b8 6e da 0c 06 08}  //weight: 10, accuracy: Low
        $x_2_2 = "Load" wide //weight: 2
        $x_2_3 = "EntryPoint" wide //weight: 2
        $x_2_4 = "Purityx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEDW_2147847433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEDW!MTB"
        threat_id = "2147847433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 28 54 00 00 0a 72 ?? 30 01 70 18 18 28 54 05 00 06 0b 07 28 55 00 00 0a 0c 08 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "omar_iraq" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_CEN_2147847511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.CEN!MTB"
        threat_id = "2147847511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 2d 00 00 0a 0d 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 1f 2c 9d 28 ?? ?? ?? 0a 13 04 7e ?? ?? ?? 0a 13 05 16 13 06 16 13 07 06}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsApplication1.My" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ABXZ_2147848015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ABXZ!MTB"
        threat_id = "2147848015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 18 8c ?? 00 00 01 a2 14 14 28 ?? 00 00 0a 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 7b ?? 00 00 04 16 02 7b ?? 00 00 04 8e 69 6f ?? 00 00 0a 0c 08 28 ?? 00 00 06 00 02 28 ?? 00 00 06 00 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NN_2147850318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NN!MTB"
        threat_id = "2147850318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 02 11 ?? 91 06 11 05 08 5d 91 61 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NN_2147850318_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NN!MTB"
        threat_id = "2147850318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 6f d1 00 00 06 13 06 06 6f ?? 00 00 06 13 07 11 06 8d ?? 00 00 01 13 08 06 11 08 16 11 08 8e 69 6f ?? 00 00 0a 26 11 08 73 ?? 00 00 06 07 11 05 11 07 6f ?? 00 00 06 26 11 05 11 07 58 13 05 11 05 11 04 32 ba}  //weight: 5, accuracy: Low
        $x_1_2 = "djkdkdk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAGS_2147851424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAGS!MTB"
        threat_id = "2147851424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {20 b9 d7 5b 0f 28 ?? 00 00 06 80 ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 80 ?? 00 00 04 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "zbe.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAHQ_2147851739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAHQ!MTB"
        threat_id = "2147851739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 72 6e d0 01 70 72 72 d0 01 70 6f ?? 00 00 0a 10 00 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0a 16 0b 38 ?? 00 00 00 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 06 9c 20 04 00 00 00 38 ?? 00 00 00 09 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAHV_2147851848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAHV!MTB"
        threat_id = "2147851848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAMC_2147888516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAMC!MTB"
        threat_id = "2147888516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 8e b7 17 da 17 d6 8d ?? 00 00 01 0b 16 13 05 00 11 0a 11 0c 11 06 6f ?? 00 00 0a 13 0d 00 00 11 08 73 ?? 00 00 0a 13 0e 00 00 11 0e 11 0d 16 73 ?? 00 00 0a 13 0f 00 11 0f 07 16 07 8e b7 6f ?? 00 00 0a 13 05 11 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AANA_2147888948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AANA!MTB"
        threat_id = "2147888948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1c 13 0e 38 ?? fe ff ff 11 06 17 58 13 06 1f 09 13 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAQV_2147892089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAQV!MTB"
        threat_id = "2147892089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 11 11 0f 73 ?? 00 00 0a 11 11 07 11 0c 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 0b 1a 8d ?? 00 00 01 13 0e 11 0b 11 0e 16 1a 6f ?? 00 00 0a 26 11 0e 16 28 ?? 00 00 0a 13 08 73 ?? 00 00 06 13 0a 1b 8d ?? 00 00 01 13 04 11 0b 11 04 16 1b 6f ?? 00 00 0a 26 11 0a 11 04}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_MBJX_2147893002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.MBJX!MTB"
        threat_id = "2147893002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 04 00 fe 0c 03 00 6f ?? 00 00 0a 5a 58 fe 0e 05 00 20 00 00 00 00 fe 0e 06 00 38 98 00 00 00 fe 09 00 00 fe 0c 06 00 fe 0c 04 00 28 ?? 00 00 0a fe 0e 07 00 fe 0c 05 00 fe 0c 06 00}  //weight: 1, accuracy: Low
        $x_1_2 = "4593-B458-2ED713DEA7E1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEAH_2147894539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEAH!MTB"
        threat_id = "2147894539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f ?? 00 00 0a 2b ee 28 ?? 00 00 0a 2b eb}  //weight: 10, accuracy: Low
        $x_10_2 = {2a 2b 18 14 2b 18 16 2d eb 2a 28 ?? 00 00 06 2b df 28 ?? 00 00 0a 2b da 0a 2b d9 06 2b e5 6f ?? 00 00 0a 2b e1}  //weight: 10, accuracy: Low
        $x_5_3 = "Powered by SmartAssembly 8.1.0.4892" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAVK_2147895295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAVK!MTB"
        threat_id = "2147895295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 6a 13 07 16 0c 18 13 12 2b c2 d0 ?? 00 00 04 26 2b 51 1c 13 12 2b b5 d0 ?? 00 00 04 19 18 33 03 26 2b 01 26 01 11 0d 11 0c 11 09 17 28 ?? 00 00 06 11 06 11 07 6f ?? 00 00 06 11 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_MBEN_2147895386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.MBEN!MTB"
        threat_id = "2147895386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 23 28 ee 00 00 0a 72 0b 16 00 70}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 46 00 6f 00 41 00 53 00 41 00 41 00 41 00 45 00 63 00 74 00 38 00 41 00 41 00 48 00 43 00 41 00 45 00 77 00 41 00 41 00 42 00 42 00 53 00 41 00 46 00 41 00 41 00 41 00 42 00 48}  //weight: 1, accuracy: High
        $x_1_3 = "FB_Checker.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAWJ_2147896287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAWJ!MTB"
        threat_id = "2147896287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 0d 07 8e 69 13 04 11 04 09 8e 69 fe 02 13 05 11 05 2c 05 09 8e 69 13 04 07 09 11 04 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b af 06 09 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b 97 06 6f ?? 00 00 0a 13 06 2b 0a 6f ?? 00 00 0a 38 ?? ff ff ff 11 06 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAWK_2147896294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAWK!MTB"
        threat_id = "2147896294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 0d 07 8e 69 13 04 11 04 09 8e 69 fe 02 13 05 11 05 2c 02 2b 05 2b 0d 0c 2b e5 09 8e 69 13 04 2b 03 0b 2b d2 07 09 11 04 28 ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b b3 06 09 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b 9b 06 09 6f ?? 00 00 0a 2b 0a 6f ?? 00 00 0a 38 ?? ff ff ff 06 6f ?? 00 00 0a 13 06 2b 0a 6f ?? 00 00 0a 38 ?? ff ff ff 11 06 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAWL_2147896322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAWL!MTB"
        threat_id = "2147896322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 8e 69 13 04 11 04 09 8e 69 fe 02 13 05 2b 03 0d 2b ed 11 05 2c 02 2b 05 2b 0d 0c 2b df 09 8e 69 13 04 2b 03 0b 2b cc 07 09 11 04 28 ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b ad 06 09 6f ?? 00 00 0a 2b 07 6f ?? 00 00 0a 2b 95 06 09 6f ?? 00 00 0a 2b 0a 6f ?? 00 00 0a 38 ?? ff ff ff 06 6f ?? 00 00 0a 13 06 2b 0a 6f ?? 00 00 0a 38 ?? ff ff ff 11 06 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_KAB_2147896393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.KAB!MTB"
        threat_id = "2147896393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 11 04 11 07 11 05 59 91 1f 28 61 d2 61 d2 81 ?? 00 00 01 11 07 17 58 13 07 17 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_KAC_2147896406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.KAC!MTB"
        threat_id = "2147896406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 00 41 00 67 00 41 00 41 00 41 00 52 00 79 00 76 00 51 00 41 00 41 00 63 00 49 00 41 00 4a 00 41 00 41 00 41}  //weight: 1, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_KAD_2147896408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.KAD!MTB"
        threat_id = "2147896408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 45 11 46 02 12 16 7b ?? ?? 00 04 6e 11 46 6a d6 b7 91 9c 11 46 17 d6 13 46 11 46 11 5d 31 e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NBL_2147896419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NBL!MTB"
        threat_id = "2147896419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 e2 5f 85 cd 65 20 d8 9a 7e 28 61 20 3a c5 fb e5 58 17 62 13 05}  //weight: 1, accuracy: High
        $x_1_2 = {20 dd f2 d6 37 20 40 af 40 10 59 20 1d 43 96 27 61 1a 63 19 63 07 5b 0b}  //weight: 1, accuracy: High
        $x_1_3 = {20 b9 e4 fb 48 20 06 ba 66 21 59 65 20 1d 6f a2 10 58 20 95 bb f2 16 61 66 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NL_2147898267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NL!MTB"
        threat_id = "2147898267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 05 11 06 8f 09 00 00 01 25 71 09 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 09 00 00 01 1f 62 28 de 00 00 06 39 1d f6 ff ff}  //weight: 3, accuracy: High
        $x_3_2 = {11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0f 38 f7 04 00 00 38 a2 02 00 00 1f 09 38 bf fe ff ff}  //weight: 3, accuracy: High
        $x_3_3 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 16}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NL_2147898267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NL!MTB"
        threat_id = "2147898267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0e 53 00 fe 0c 6d 00 fe 0c 6d 00 1f 17 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 77 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1d 64 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 55 00 58 fe 0e 6d 00 fe 0c 6d 00 fe 0c 6d 00 1e 62 61 fe 0e 6d 00 fe 0c 6d 00 fe 0c 53 00 58 fe 0e 6d 00 fe 0c 55 00 1b 62 fe 0c 77 00 58 fe 0c 55 00 61 fe 0c 6d 00 59 fe 0e 6d 00 fe 0c 6d 00 76 6c 6d 58 13 41}  //weight: 1, accuracy: High
        $x_1_2 = {62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 1c 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1d 64 61 fe 0e 26 00 fe 0c 26 00 fe 0c 23 00 58 fe 0e 26 00 fe 0c 26 00 fe 0c 26 00 1e 62 61 fe 0e 26 00 fe 0c 26 00 fe 0c 13 00 58 fe 0e 26 00 fe 0c 23 00 1b 62 fe 0c 1c 00 58 fe 0c 23 00 61 fe 0c 26 00 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AAZK_2147898790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AAZK!MTB"
        threat_id = "2147898790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 11 04 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 00 11 06 11 05 17 73 ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
        $x_2_2 = {13 09 11 07 11 09 16 11 09 8e 69 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 13 0a}  //weight: 2, accuracy: Low
        $x_1_3 = "8asdHnjsaeO1w1Mo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_MBFQ_2147899064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.MBFQ!MTB"
        threat_id = "2147899064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 41 00 51 00 71 00 56 00 54 00 00 19 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 00 09 4c 00 6f 00 61 00 64 00 00 19 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 01 15 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PSA_2147899279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PSA!MTB"
        threat_id = "2147899279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 06 00 00 04 d0 01 ?? ?? ?? 28 14 ?? ?? ?? 6f 15 ?? ?? ?? 2c 20 72 01 00 00 70 16 8d 15 00 00 01 28 16 ?? ?? ?? 73 17 ?? ?? ?? 7a 73 18 ?? ?? ?? 80 06 00 00 04 7e 06 00 00 04 d0 01 ?? ?? ?? 28 14 ?? ?? ?? 14 6f 19 ?? ?? ?? 28 01 00 00 2b 0a de 6c}  //weight: 5, accuracy: Low
        $x_1_2 = "StrangeCRC" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "kZZAIAO5YjoLRIAUdw" ascii //weight: 1
        $x_1_6 = "LILZyRumYgPWakc6Iy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_BCAA_2147900900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.BCAA!MTB"
        threat_id = "2147900900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 16 8c ?? 00 00 01 a2 14 14 28 ?? 00 00 0a 11 0b 17 59 17 58 17 59 17 58 17 59 17 58 8d ?? 00 00 01 13 0c 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PADK_2147902483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PADK!MTB"
        threat_id = "2147902483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 07 11 0c 07 8e 69 5d 91 d7 11 05 11 0c 95 d7 6e 20 ff 00 00 00 6a 5f b8 0d}  //weight: 1, accuracy: High
        $x_1_2 = {11 05 09 84 11 04 9e 11 06 11 07 02 11 07 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_CCHT_2147903236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.CCHT!MTB"
        threat_id = "2147903236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%payload%" wide //weight: 1
        $x_1_2 = "private.RunPE" wide //weight: 1
        $x_1_3 = "TVqQA&M&&&AM&&&&E&A&&&E&&&&A&&E&&&&//A&E&&&&" wide //weight: 1
        $x_1_4 = "g&&&&&4fug4&t&nNIb" wide //weight: 1
        $x_1_5 = "ZGUuDQAg&&&&&4fug4&t&nNIbgB" wide //weight: 1
        $x_1_6 = "m5vdCBiZSBydW4gaW4gRE9TIG1v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_MBYR_2147913546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.MBYR!MTB"
        threat_id = "2147913546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQ**-****-**M**-****-****-****-**E**-****-****-****-**//8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PPD_2147917933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PPD!MTB"
        threat_id = "2147917933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 03 28 ?? ?? ?? 0a 04 08 5d 6c 58 28 ?? ?? ?? 0a b8 6e da 0b 06 07 b7 28 ?? ?? ?? 0a 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 0a 11 04 17 d6 13 04 11 04 09 31 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PAFP_2147921707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PAFP!MTB"
        threat_id = "2147921707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "L2MgUG93ZXJTaGVsbC5leGUgLXdpbmRvd3N0eWxlIGhpZGRlbiBBZGQtTXBwcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoIA==" wide //weight: 2
        $x_2_2 = "ZXhwbG9yZXIuZXhl" wide //weight: 2
        $x_2_3 = "Q29ydGFuYS5leGU=" wide //weight: 2
        $x_2_4 = "U3lzdGVtU2V0dGluZ3MuZXhl" wide //weight: 2
        $x_2_5 = "VGFza21nci5leGU" wide //weight: 2
        $x_1_6 = "\\Microsoft\\Windows\\" ascii //weight: 1
        $x_2_7 = "/c PowerShell.exe -windowstyle hidden Add-Mppreference -ExclusionPath" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AYA_2147922982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AYA!MTB"
        threat_id = "2147922982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$e1ae280a-f0b2-43ae-9cc4-3e4a4e9c76a7" ascii //weight: 2
        $x_1_2 = "casa 54" ascii //weight: 1
        $x_1_3 = "obj\\Release\\Software.pdb" ascii //weight: 1
        $x_1_4 = "Software.Resources" ascii //weight: 1
        $x_1_5 = "Property can only be set to Nothing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_SAB_2147931942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.SAB!MTB"
        threat_id = "2147931942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Add-MpPreference -ExclusionPath '" wide //weight: 1
        $x_1_3 = "Stop-Process -Name 'SecurityHealthSystray' -Force;" wide //weight: 1
        $x_1_4 = "-ExecutionPolicy Bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEPA_2147932664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEPA!MTB"
        threat_id = "2147932664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 02 07 91 1f 09 61 d2 9c 07 1f 09 58 0b 07 08 31 ed}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_GPPE_2147932775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.GPPE!MTB"
        threat_id = "2147932775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {02 03 20 00 7e 00 00 5d 91 0a 06 7e 03 00 00 04 03 1f 16 5d 28}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_SPA_2147934649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.SPA!MTB"
        threat_id = "2147934649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$atalhoStartup = \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk\"" ascii //weight: 2
        $x_2_2 = "Invoke-WebRequest -Uri $encURL -OutFile $encPath" ascii //weight: 2
        $x_2_3 = "$scriptDescriptografia = \"$dirBase\\update.ps1\"" ascii //weight: 2
        $x_2_4 = "$Atalho.Arguments = \"-ExecutionPolicy Bypass -WindowStyle Hidden -File" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ZZO_2147938257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ZZO!MTB"
        threat_id = "2147938257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 11 05 6f ?? 00 00 0a 00 11 04 13 06 09 6f ?? 00 00 0a 13 07 11 07 11 06 20 ff ff ff ff 20 2f 01 00 00 20 d9 0b 00 00 fe 04 69 58 11 06 8e 69 6f ?? 00 00 0a 13 08 11 08 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_NEPB_2147939512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.NEPB!MTB"
        threat_id = "2147939512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 16 11 05 6f 73 00 00 0a 00 08 06 16 06 8e b7 6f 7f 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06 2d db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PGG_2147939515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PGG!MTB"
        threat_id = "2147939515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 06 11 06 16 06 06 14 6f ?? ?? ?? 0a a2 00 11 06 17 14 a2 00 11 06 14 14 14 17 28 ?? ?? ?? 0a 26 00 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_PGN_2147940184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.PGN!MTB"
        threat_id = "2147940184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 07 6c 23 00 00 00 00 00 00 00 40 5b 28 ?? 00 00 0a b7 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 11 07 18 d6 13 07 11 07 11 0b 13 0d 11 0d 31 ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ABUA_2147941477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ABUA!MTB"
        threat_id = "2147941477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 03 00 fe 0c 02 00 9a fe 0e 01 00 fe 0c 00 00 fe 0c 01 00 20 02 00 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 02 00 20 01 00 00 00 d6 fe 0e 02 00 fe 0c 02 00 fe 0c 03 00 8e b7 3f ?? ff ff ff fe 0c 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_BAA_2147941712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.BAA!MTB"
        threat_id = "2147941712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 09 11 0d 11 0e 11 0c 11 0e 59 ?? ?? ?? ?? ?? 13 0f 11 0f 16 fe 01 16 fe 01 13 13 11 13 2d 02 2b 14 11 0e 11 0f 58 13 0e 00 11 0e 11 0c fe 04 13 13 11 13 2d c9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_BAA_2147941712_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.BAA!MTB"
        threat_id = "2147941712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 25 00 00 0a 0c 08 07 ?? ?? 00 00 0a 17 73 27 00 00 0a 0d 09 02 16 02 8e b7 ?? ?? 00 00 0a 09 ?? ?? 00 00 0a de 0a 09 2c 06 09 ?? ?? 00 00 0a dc 08 ?? ?? 00 00 0a 0a de 18 de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AUYA_2147945577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AUYA!MTB"
        threat_id = "2147945577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 0d 13 0e 38}  //weight: 5, accuracy: Low
        $x_2_2 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 00 11 08 08 fe 04 2d da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_AGZA_2147945947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.AGZA!MTB"
        threat_id = "2147945947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 17 da 0c 16 0d 2b 3b 06 6f ?? 00 00 0a 17 da 13 04 16 13 05 2b 22 7e ?? 00 00 04 06 11 05 09 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 17 d6 13 05 11 05 11 04 31 d8 09 17 d6 0d 09 08 31 c1 7e ?? 00 00 04 6f ?? 00 00 0a 0b 07 28 ?? 00 00 06 2c 15}  //weight: 4, accuracy: Low
        $x_2_2 = {20 0f 27 00 00 8d ?? 00 00 01 0d 73 ?? 00 00 0a 0a 72 ?? 00 00 70 d0 ?? 00 00 01 28 ?? 00 00 0a 06 6f ?? 00 00 0a d0 ?? 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 0c 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ARAB_2147947461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ARAB!MTB"
        threat_id = "2147947461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 02 06 91 11 05 61 11 04 08 91 61 b4 9c 08 03 6f ?? 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 06 17 d6 0a 06 11 06 31 d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ARBB_2147948566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ARBB!MTB"
        threat_id = "2147948566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 03 09 03 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a 28 ?? 00 00 0a da 13 04 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 09 17 d6 0d 00 09 08 fe 02 16 fe 01 13 05 11 05}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ABCB_2147948830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ABCB!MTB"
        threat_id = "2147948830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 11 05 9a 28 ?? 00 00 06 13 06 12 04 11 04 8e 69 11 06 8e 69 58 28 ?? 00 00 2b 11 06 16 11 04 11 04 8e 69 11 06 8e 69 59 11 06 8e 69 28 ?? 00 00 06 11 05 17 58 13 05 11 05 06 8e 69 32 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_ACCB_2147948831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.ACCB!MTB"
        threat_id = "2147948831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 11 06 9a 28 ?? 00 00 06 13 07 11 05 11 07 6f ?? 00 00 0a 11 06 17 58 13 06 11 06 06 8e 69 32 de 11 05 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 08 11 08 08 28 ?? 00 00 06 11 08 09 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 09 11 09 11 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_SLJK_2147949349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.SLJK!MTB"
        threat_id = "2147949349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 01 00 00 04 28 04 00 00 0a 72 01 00 00 70 7e 02 00 00 04 28 05 00 00 0a 02 50 28 06 00 00 0a 28 09 00 00 06 26 02 50 2a}  //weight: 2, accuracy: High
        $x_2_2 = {1b 8d 06 00 00 01 0a 06 16 72 12 d6 0a 70 a2 06 17 7e 01 00 00 04 a2 06 18 72 01 00 00 70 a2 06 19 7e 02 00 00 04 a2 06 1a 72 8e d6 0a 70 a2 06 28 0b 00 00 0a 18 16 15 28 0c 00 00 0a 8c 0b 00 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRat_SLCN_2147951563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRat.SLCN!MTB"
        threat_id = "2147951563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 bb 02 00 70 02 28 0d 00 00 06 03 17 18 8d 01 00 00 01 0a 06 16 72 2d 03 00 70 28 1e 00 00 06 a2 06 17 72 9b 03 00 70 28 1e 00 00 06 a2 06 28 32 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

