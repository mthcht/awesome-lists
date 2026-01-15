rule Trojan_Win64_SubtleSolution_A_2147961138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SubtleSolution.A!dha"
        threat_id = "2147961138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SubtleSolution"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Implant graceful shutdown" ascii //weight: 10
        $x_10_2 = "struct ImplantId" ascii //weight: 10
        $x_10_3 = "struct ImplantConfig" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SubtleSolution_B_2147961139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SubtleSolution.B!dha"
        threat_id = "2147961139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SubtleSolution"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Failed to initialize implant" ascii //weight: 10
        $x_10_2 = "splinter_core" ascii //weight: 10
        $x_10_3 = "C2.Serialization" ascii //weight: 10
        $x_10_4 = "struct ImplantConfig" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

