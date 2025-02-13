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

