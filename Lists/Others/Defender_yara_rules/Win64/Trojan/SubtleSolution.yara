rule Trojan_Win64_SubtleSolution_A_2147959523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SubtleSolution.A"
        threat_id = "2147959523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SubtleSolution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Implant graceful shutdown" ascii //weight: 10
        $x_10_2 = "struct ImplantId" ascii //weight: 10
        $x_10_3 = "struct ImplantConfig" ascii //weight: 10
        $x_1_4 = "tmp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

