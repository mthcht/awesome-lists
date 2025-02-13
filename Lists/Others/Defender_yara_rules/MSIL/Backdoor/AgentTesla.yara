rule Backdoor_MSIL_AgentTesla_F_2147730131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla.F!MTB"
        threat_id = "2147730131"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 [0-11] 8e 69 5d 91 61 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = "$e2a361a6-78a0-40d1-89c0-89327d89adf8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_2147741685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla!MTB"
        threat_id = "2147741685"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 16 00 03 6f ?? ?? 00 0a ?? 28 ?? ?? 00 0a ?? 3b ?? ?? 00 00 72 ?? ?? 00 70 28 ?? ?? 00 06 38 ?? ?? 00 00 72 ?? ?? 00 70 28 ?? ?? 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_2147741685_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla!MTB"
        threat_id = "2147741685"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 06 13 05 08 72 ?? 00 00 70 50 00 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 0c 07 ?? ?? ?? ?? ?? 72 ?? 00 00 70 28 ?? 00 00 06 ?? ?? ?? ?? ?? 28 ?? 00 00 06 0d 08 72 ?? 00 00 70 28 ?? 00 00 06 13 04 08 72 ?? 00 00 70 28 ?? 00 00 06 13 05 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_2147741685_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla!MTB"
        threat_id = "2147741685"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 11 04 7b ?? 00 00 04 a2 25 50 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 72 ?? ?? 00 70 6f ?? 00 00 0a 0b 07 72 ?? ?? 00 70 6f ?? 00 00 0a 0c 07 28 ?? 00 00 0a 0d 73 ?? 00 00 06 13 ?? 1f ?? 8d ?? 00 00 01 25 16 11 04 7b ?? 00 00 04 a2 25 17 11 04 7b ?? 00 00 04 a2 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_AD_2147741809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla.AD!MTB"
        threat_id = "2147741809"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 22 01 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a [0-5] 6f ?? ?? ?? 0a 72 2e 01 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a [0-10] 72 38 01 00 70 6f ?? ?? ?? 0a [0-5] 72 3c 01 00 70 6f ?? ?? ?? 0a [0-5] 72 40 01 00 70 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_AD_2147741809_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla.AD!MTB"
        threat_id = "2147741809"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_2 = "SecureTeam.Attributes.ObfuscatedByAgileDotNetAttribute" ascii //weight: 1
        $x_1_3 = "YanoAttribute" ascii //weight: 1
        $x_1_4 = "ZYXDNGuarder" ascii //weight: 1
        $x_1_5 = "SmartAssembly.Attributes.PoweredByAttribute" ascii //weight: 1
        $x_1_6 = "ILProtector" ascii //weight: 1
        $x_1_7 = "SecureTeam.Attributes.ObfuscatedByCliSecureAttribute" ascii //weight: 1
        $x_1_8 = "Xenocode.Client.Attributes.AssemblyAttributes.ProcessedByXenocode" ascii //weight: 1
        $x_1_9 = "ILoveTheRealGiths" ascii //weight: 1
        $x_1_10 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_11 = "BabelObfuscatorAttribute" ascii //weight: 1
        $x_1_12 = "Centos" ascii //weight: 1
        $x_1_13 = "DotfuscatorAttribute" ascii //weight: 1
        $x_1_14 = "EMyPID_8234_" ascii //weight: 1
        $x_1_15 = "CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute" ascii //weight: 1
        $x_1_16 = "NineRays.Obfuscator.Evaluation" ascii //weight: 1
        $x_5_17 = {80 9a 01 00 80 94 5f 5f 5f 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (5f) (5f) 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 12 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_AgentTesla_SBR_2147755606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla.SBR!MSR"
        threat_id = "2147755606"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hupigdhiypoagdpiydgpidygdi" ascii //weight: 1
        $x_1_2 = "Encrypted" wide //weight: 1
        $x_1_3 = "newworldorde" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_AgentTesla_SBR1_2147755714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AgentTesla.SBR1!MSR"
        threat_id = "2147755714"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 28 65 00 00 06 72 ?? 00 00 70 28 11 00 00 06 0a 28 2f 00 00 0a 06 6f 30 00 00 0a 0b 07 6f 31 00 00 0a 17 9a 0c 08 72 ?? 00 00 70 20 00 01 00 00 14 14 18 8d 04 00 00 01 25 16 7e 08 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

