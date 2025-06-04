rule Trojan_MSIL_KatzStealer_DA_2147942805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KatzStealer.DA!MTB"
        threat_id = "2147942805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KatzStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecutarMetodoVAI" ascii //weight: 1
        $x_1_2 = "VirtualMachineDetector" ascii //weight: 1
        $x_1_3 = "Wow64SetThreadContext_API" ascii //weight: 1
        $x_1_4 = "nomedoarquivo" ascii //weight: 1
        $x_1_5 = "payloadBuffer" ascii //weight: 1
        $x_1_6 = "caminhovbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

