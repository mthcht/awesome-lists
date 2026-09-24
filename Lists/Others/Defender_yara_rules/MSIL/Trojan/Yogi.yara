rule Trojan_MSIL_Yogi_A_2147978734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Yogi.A!MTB"
        threat_id = "2147978734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[stage] payload bytes:" wide //weight: 1
        $x_1_2 = "[stage] JNI_OnLoad export not found" wide //weight: 1
        $x_1_3 = "[stage] mapped base = 0x" wide //weight: 1
        $x_1_4 = "[mapper] GetProcAddress failed in" wide //weight: 1
        $x_1_5 = "[mapper] VirtualProtect failed on section" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

