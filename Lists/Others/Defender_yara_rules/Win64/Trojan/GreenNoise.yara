rule Trojan_Win64_GreenNoise_DA_2147977374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreenNoise.DA!MTB"
        threat_id = "2147977374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreenNoise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GreenNoise.pdb" ascii //weight: 1
        $x_1_2 = "\\BaseNamedObjects\\{" ascii //weight: 1
        $x_1_3 = "NtCreateSection" ascii //weight: 1
        $x_1_4 = "NtMapViewOfSection" ascii //weight: 1
        $x_1_5 = "NtOpenSection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

