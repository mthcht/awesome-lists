rule Ransom_Win64_Nobody_MX_2147961612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nobody.MX!MTB"
        threat_id = "2147961612"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nobody"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".nobodycry" ascii //weight: 5
        $x_1_2 = "ProgramData\\nobody.exe" ascii //weight: 1
        $x_1_3 = "Nobodycrypt" ascii //weight: 1
        $x_1_4 = "Rusocrypt" ascii //weight: 1
        $x_1_5 = "Local\\nobodyrmrf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

