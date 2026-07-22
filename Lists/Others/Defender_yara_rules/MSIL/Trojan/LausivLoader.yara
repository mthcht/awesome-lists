rule Trojan_MSIL_LausivLoader_NYA_2147973652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LausivLoader.NYA!MTB"
        threat_id = "2147973652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LausivLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "preserve-name" ascii //weight: 1
        $x_1_2 = "DefineDynamicAssembly" ascii //weight: 1
        $x_2_3 = "tQaCQYKIo1FdSsme" ascii //weight: 2
        $x_1_4 = "NoLogo -NonInteractive -WindowStyle Hidden -Command" ascii //weight: 1
        $x_1_5 = "IsAttached" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_2_7 = "F-H/Y1`2e7i" wide //weight: 2
        $x_1_8 = {4c 00 61 00 4c 00 62 00 4c 00 63 00 4c 00 64 00 4c 00 65 00 4c 00 66 00 4c 00 67 00 4c 00 68 00 4c 00 6c 00 6b 00 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LausivLoader_NYD_2147974306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LausivLoader.NYD!MTB"
        threat_id = "2147974306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LausivLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "preserve-name" ascii //weight: 1
        $x_1_2 = "DefineDynamicAssembly" ascii //weight: 1
        $x_2_3 = "tQaCQYKIo1FdSsme" ascii //weight: 2
        $x_1_4 = "NoLogo -NonInteractive -WindowStyle Hidden -Command" ascii //weight: 1
        $x_1_5 = "IsAttached" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_2_7 = {00 44 00 46 00 45 00 47 00 44 00 48 00 47 00 4b 00 4a 00 4d 00 4c 00 4e 00 4c 00 4f 00 4c 00 50 00 4c 00 51 00 4c 00 52}  //weight: 2, accuracy: High
        $x_1_8 = {4c 00 61 00 4c 00 62 00 4c 00 63 00 4c 00 64 00 4c 00 65 00 4c 00 66 00 4c 00 67 00 4c 00 68 00 4c 00 6c 00 6b 00 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

