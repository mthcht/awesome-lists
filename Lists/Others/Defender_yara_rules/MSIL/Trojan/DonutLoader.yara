rule Trojan_MSIL_DonutLoader_EAEP_2147935748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.EAEP!MTB"
        threat_id = "2147935748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 12 02 7b 0f 00 00 04 28 07 00 00 0a 2c 0a 12 02 7b 08 00 00 04 0a 2b 0a 07 12 02 28 ?? ?? ?? 06 2d dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_ZGL_2147955953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.ZGL!MTB"
        threat_id = "2147955953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 3a 74 ff ff ff 06 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_SJZ_2147963926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.SJZ!MTB"
        threat_id = "2147963926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DecryptShellcode" ascii //weight: 1
        $x_1_2 = "BlandRootkit" ascii //weight: 1
        $x_1_3 = "Global\\BlandRootkitInstance" ascii //weight: 1
        $x_1_4 = "WinSecUpdate" ascii //weight: 1
        $x_1_5 = "sc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_SJ_2147964556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.SJ!MTB"
        threat_id = "2147964556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 0b 00 00 70 72 05 00 00 70 6f 11 00 00 0a 72 0f 00 00 70 72 05 00 00 70 6f 11 00 00 0a 10 02 03 28 12 00 00 0a 0a 04 28 12 00 00 0a 0b 28 13 00 00 0a 0c 08 06 6f 14 00 00 0a 08 07 6f 15 00 00 0a 08 17 6f 16 00 00 0a 08 18 6f 17 00 00 0a 73 18 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_BA_2147966174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.BA!MTB"
        threat_id = "2147966174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d0 07 00 00 01 28 07 00 00 0a 72 01 00 00 70 17 8d 08 00 00 01 25 16 d0 02 00 00 1b 28 07 00 00 0a a2 28 08 00 00 0a 14 17 8d 04 00 00 01 25 16 28 04 00 00 06 a2 ?? ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_ARL_2147973801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.ARL!MTB"
        threat_id = "2147973801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 8e 69 0d 2b 06 00 09 17 59 0d 00 09 16 31 0e 08 09 17 59 91 20 ?? 00 00 00 fe 01 2b 01 16 00 13 10}  //weight: 1, accuracy: Low
        $x_2_2 = {11 08 12 05 12 06 28 ?? 00 00 06 13 09 11 09 13 10 11 10 2d 09 00 16 13 0f dd a6 00 00 00 12 06 7b ?? 00 00 04 13 0a 12 06 7b ?? 00 00 04 0a 06 7e ?? 00 00 0a 11 04 8e 69 20 00 30 00 00 1a 28 ?? 00 00 06 13 0b 16 13 0c 06 11 0b 11 04 11 04 8e 69 12 0c 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_AUL_2147973802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.AUL!MTB"
        threat_id = "2147973802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 11 0a 1f 0c 72 ?? 00 00 70 a2 11 0a 1f 0d 72 ?? 00 00 70 a2 11 0a 1f 0e 72 ?? 00 00 70 a2 11 0a 0d 28 ?? 00 00 0a 13 0b 16 13 0c 2b 4b 11 0b 11 0c 9a 13 04 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 09 13 0d 16 13 0e 2b 20 11 0d 11 0e 9a 13 06 11 05 11 06 6f ?? 00 00 0a 2c 08 17 13 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

