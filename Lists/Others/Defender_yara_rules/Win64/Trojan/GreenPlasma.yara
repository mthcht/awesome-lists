rule Trojan_Win64_GreenPlasma_DA_2147969146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreenPlasma.DA!MTB"
        threat_id = "2147969146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreenPlasma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NtCreateSymbolicLinkObject" ascii //weight: 1
        $x_1_2 = "Failed to create object manager link." ascii //weight: 1
        $x_1_3 = "CTFMON_DEAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

