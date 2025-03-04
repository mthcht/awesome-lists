rule Backdoor_MSIL_LimeRat_GA_2147776762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/LimeRat.GA!MTB"
        threat_id = "2147776762"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[DAE]" ascii //weight: 1
        $x_1_2 = "[URL]" ascii //weight: 1
        $x_1_3 = "[NAME]" ascii //weight: 1
        $x_1_4 = "[FILELOCA]" ascii //weight: 1
        $x_1_5 = "[Tskmgr]" ascii //weight: 1
        $x_1_6 = "[WindDef]" ascii //weight: 1
        $x_1_7 = "[Registry]" ascii //weight: 1
        $x_1_8 = "DisableRegistryTools" ascii //weight: 1
        $x_1_9 = "DisableTaskMgr" ascii //weight: 1
        $x_1_10 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_11 = "ProcessName" ascii //weight: 1
        $x_1_12 = "nur\\noisrevtnerruc\\swodniw\\tfosorcim\\erawtfos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Backdoor_MSIL_LimeRat_AY_2147850254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/LimeRat.AY!MTB"
        threat_id = "2147850254"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 01 00 00 0a 1f 28 8d 02 00 00 01 25 d0 01 00 00 04 28 02 00 00 0a 6f 03 00 00 0a 0a 28 01 00 00 0a 1f 28 8d 02 00 00 01 25}  //weight: 2, accuracy: High
        $x_2_2 = {0a 1f 28 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 1f 28 8d ?? 00 00 01 25}  //weight: 2, accuracy: Low
        $x_2_3 = "CreateDecryptor" ascii //weight: 2
        $x_2_4 = "TransformFinalBlock" ascii //weight: 2
        $x_2_5 = "SymmetricAlgorithm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

