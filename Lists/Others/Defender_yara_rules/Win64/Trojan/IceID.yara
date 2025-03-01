rule Trojan_Win64_IceID_NL_2147830311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceID.NL!MTB"
        threat_id = "2147830311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 1e fa 80 35 e5 d1 04 00 28 80 35 df d1 04 00 28 80 35 d9 d1 04 00 28 80 35 d3 d1 04 00 28 80 35 cd d1 04 00 28 80 35 c7 d1 04 00 28 80 35 c1 d1 04 00 28 80 35 bb d1 04 00 28 80 35 b5 d1 04 00 28 80 35 af d1 04 00 28 80 35 a9 d1 04 00 28}  //weight: 1, accuracy: High
        $x_1_2 = {80 35 97 d1 04 00 47 80 35 91 d1 04 00 47 80 35 8b d1 04 00 47 80 35 85 d1 04 00 47 80 35 7f d1 04 00 47 80 35 79 d1 04 00 47 80 35 73 d1 04 00 47 80 35 6d d1 04 00 47 80 35 67 d1 04 00 47 80 35 61 d1 04 00 47 80 35 5b d1 04 00 47 80 35 55 d1 04 00 47 80 35 4f d1 04 00 47 80 35 49 d1 04 00 47 80 35 43 d1 04 00 47 0f 28 05 41 d1 04 00 0f 57 05 ca 7e 00 00 0f 29 05 33 d1 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IceID_SK_2147834675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceID.SK!MTB"
        threat_id = "2147834675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yugaenjakdsuhygfruhjwekuhewbyujass" ascii //weight: 5
        $x_5_2 = "gyuasifiisdygaisjdoifguhyugasjsjuh" ascii //weight: 5
        $x_2_3 = "CreateEventW" ascii //weight: 2
        $x_2_4 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_IceID_A_2147890067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceID.A!MTB"
        threat_id = "2147890067"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 30 ?? 30 41 ff e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

