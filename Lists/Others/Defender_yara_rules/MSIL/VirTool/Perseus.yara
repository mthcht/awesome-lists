rule VirTool_MSIL_Perseus_AB_2147745502_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Perseus.AB!MTB"
        threat_id = "2147745502"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de4fuckyou" ascii //weight: 1
        $x_1_2 = "VMProtect" ascii //weight: 1
        $x_1_3 = "Beds-Protector" ascii //weight: 1
        $x_1_4 = "CrytpoObfuscator" ascii //weight: 1
        $x_1_5 = "ObfuscatedByGoliath" ascii //weight: 1
        $x_1_6 = "OiCuntJollyGoodDayYeHavin" ascii //weight: 1
        $x_1_7 = "V2luZG93c0FwcDQk" wide //weight: 1
        $x_1_8 = "V2luZG93czkk" wide //weight: 1
        $x_1_9 = "Jumped-Over-The-Lazy-Dog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule VirTool_MSIL_Perseus_AC_2147753702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Perseus.AC!MTB"
        threat_id = "2147753702"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "QW5hcmNoeUdyYWJiZXIl" wide //weight: 1
        $x_1_2 = "_Encrypted$" wide //weight: 1
        $x_1_3 = "PROJECT_D_BYPASS" ascii //weight: 1
        $x_1_4 = {54 6f 6b 65 6e 47 72 61 62 62 65 72 [0-32] 41 6e 61 72 63 68 79 47 72 61 62 62 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 72 76 69 63 65 00 57 65 62 68 6f 6f 6b}  //weight: 1, accuracy: High
        $x_1_6 = "pbDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

