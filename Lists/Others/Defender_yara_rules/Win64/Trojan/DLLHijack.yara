rule Trojan_Win64_DLLHijack_EC_2147923737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.EC!MTB"
        threat_id = "2147923737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 08 48 8d 40 01 80 c1 4b 80 f1 3f 80 e9 4b 88 48 ff 48 83 ea 01 75 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DC_2147933584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DC!MTB"
        threat_id = "2147933584"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mpclient.dll" ascii //weight: 5
        $x_10_2 = "Hijackdll|Set COM Startup" ascii //weight: 10
        $x_10_3 = "Hijackdll|ReadBuffer" ascii //weight: 10
        $x_1_4 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
        $x_1_5 = "dllhost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DD_2147939089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DD!MTB"
        threat_id = "2147939089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mpclient.dll" ascii //weight: 5
        $x_10_2 = "C:/ProgramData/PowerToys/" ascii //weight: 10
        $x_10_3 = "d2vtkt11b1a7zs.cloudfront.net" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DE_2147939090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DE!MTB"
        threat_id = "2147939090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM msedge.exe" ascii //weight: 1
        $x_1_2 = "note.html" ascii //weight: 1
        $x_1_3 = "ransomsvc" ascii //weight: 1
        $x_1_4 = "start-fullscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_ARR_2147956040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.ARR!MTB"
        threat_id = "2147956040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {48 89 45 f8 48 8b 45 20 48 8b 4d f8 48 89 08 48 8b 45 10 38 00 48 8b 45 10 48 83 c0 ?? 48 8b 4d 10 38 09 48 8b 4d 10 48 83 c1 08 48 2b c1 48 83}  //weight: 25, accuracy: Low
        $x_5_2 = {48 8b 45 20 48 8b 8d 68 ff ff ff 48 89 08 48 8b 45 10 38 00 48 8b 45 10 48 83 c0 48 48 2b 45 10 89 85 44}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DI_2147961773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DI!MTB"
        threat_id = "2147961773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 c2 48 8d 4c 24 20 48 03 c8 0f b6 01 41 88 00 44 88 11 41 0f b6 08 49 03 ca 0f b6 c1 0f b6 4c 04 20 30 0b 48 ff c3 49 83 eb 01 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_CH_2147961785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.CH!MTB"
        threat_id = "2147961785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 8a 44 0c 40 88 44 14 40 88 5c 0c 40 0f b6 44 14 40 03 c3 0f b6 c0 8a 54 04 40 41 30 11 49 ff c1 49 83 eb 01 75 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DL_2147963407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DL!MTB"
        threat_id = "2147963407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c2 83 e0 0f 42 0f b6 0c 08 48 8d 44 24 [0-4] 48 83 7d 88 10 48 0f 43 44 24 [0-4] f6 d1 30 0c 10 48 ff c2 49 3b d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

