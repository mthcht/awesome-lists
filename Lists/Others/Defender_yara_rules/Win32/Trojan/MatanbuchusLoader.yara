rule Trojan_Win32_MatanbuchusLoader_AM_2147817425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatanbuchusLoader.AM!MTB"
        threat_id = "2147817425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatanbuchusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6001.icl" ascii //weight: 1
        $x_1_2 = "DllInstall" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "D3DKMTQueryAdapterInfo" ascii //weight: 1
        $x_1_5 = "D3DKMTOpenAdapterFromDeviceName" ascii //weight: 1
        $x_1_6 = "ct#eauRich\"eau" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MatanbuchusLoader_MA_2147821998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatanbuchusLoader.MA!MTB"
        threat_id = "2147821998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatanbuchusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ec 81 ec dc 04 00 00 33 c0 88 45 f6 8d 4d f6 e8 ea d6 ff ff 89 45 a0 8b 4d a0 0f b6 51 0c 85 d2 74 1e}  //weight: 1, accuracy: High
        $x_1_2 = "?HackCheck@@YGXXZ" ascii //weight: 1
        $x_1_3 = "DllInstall" ascii //weight: 1
        $x_1_4 = "6001.icl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MatanbuchusLoader_DF_2147821999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatanbuchusLoader.DF!MTB"
        threat_id = "2147821999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatanbuchusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a0KuQkA2.dll" ascii //weight: 2
        $x_1_2 = "A52eQa" ascii //weight: 1
        $x_1_3 = "C1lyHjvOB9" ascii //weight: 1
        $x_1_4 = "DK0VEa" ascii //weight: 1
        $x_1_5 = "KZIy9vJ00" ascii //weight: 1
        $x_1_6 = "SBPTC6EBi" ascii //weight: 1
        $x_1_7 = "U3W6ihpc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MatanbuchusLoader_DG_2147822317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatanbuchusLoader.DG!MTB"
        threat_id = "2147822317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatanbuchusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EBoeQRIw.dll" ascii //weight: 2
        $x_1_2 = "DvMOIWh9LO" ascii //weight: 1
        $x_1_3 = "EhgYL4D" ascii //weight: 1
        $x_1_4 = "FoVkX8Gn4" ascii //weight: 1
        $x_1_5 = "MZ4HkRHpJ" ascii //weight: 1
        $x_1_6 = "YbtAWMTcHY" ascii //weight: 1
        $x_1_7 = "fDNAaPd1ryr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MatanbuchusLoader_PA_2147949110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MatanbuchusLoader.PA!MTB"
        threat_id = "2147949110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MatanbuchusLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 51 20 89 55 dc 8b 45 f4 8b 4d 08 03 48 1c 89 4d cc c7 45 f0 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f0 8b 42 14 89 45 e8 33 c9 66 89 4d fc}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 ec 81 3a 50 45 00 00 74 07 33 c0 e9 ?? ?? ?? ?? 8b 45 ec}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 e8 8b 4d 08 03 48 3c 89 4d ec 8b 55 ec}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 08 89 45 f8 8b 4d f8 8b 51 3c 03 55 08}  //weight: 1, accuracy: High
        $x_1_6 = {69 c2 93 01 00 01 50 b9 01 00 00 00 c1 e1 00 03 4d 08 51 e8}  //weight: 1, accuracy: High
        $x_1_7 = {03 45 08 89 45 e0 8b 4d e0 8b 51 78 03 55 08 89 55 f0 8b 45 f0}  //weight: 1, accuracy: High
        $x_1_8 = {89 55 f4 8b 45 f4 83 78 04 00 0f 84 a6 00 00 00 8b 4d f4}  //weight: 1, accuracy: High
        $x_1_9 = {89 4d ec 8b 55 ec 81 3a 50 45 00 00 74 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

