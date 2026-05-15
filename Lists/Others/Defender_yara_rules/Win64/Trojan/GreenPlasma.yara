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

rule Trojan_Win64_GreenPlasma_DB_2147969361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreenPlasma.DB!MTB"
        threat_id = "2147969361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreenPlasma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Software\\Policies\\Microsoft\\CloudFiles" ascii //weight: 50
        $x_50_2 = "CurrentVersion\\Policies\\System" ascii //weight: 50
        $x_5_3 = "BaseNamedObjects\\CTF" ascii //weight: 5
        $x_5_4 = "CTFMON" ascii //weight: 5
        $x_5_5 = "CTF.AsmListCache" ascii //weight: 5
        $x_1_6 = "NtCreateSymbolicLinkObject" ascii //weight: 1
        $x_1_7 = "symbolic link" ascii //weight: 1
        $x_1_8 = "NtOpenSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

