rule Trojan_Win64_Zariza_MX_2147926837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zariza.MX!MTB"
        threat_id = "2147926837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zariza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hijack.dll" ascii //weight: 1
        $x_1_2 = "zig-loader.dll" ascii //weight: 1
        $x_2_3 = "deco.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Zariza_ARA_2147928716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zariza.ARA!MTB"
        threat_id = "2147928716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zariza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 00 49 8b 4c 24 e8 8a 04 01 44 28 f0 48 8b 4c 24 30 42 88 04 31 49 ff c6 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Zariza_ARAZ_2147929329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zariza.ARAZ!MTB"
        threat_id = "2147929329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zariza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 ?? 48 89 45 00 48 c7 45 08 04 00 00 00 44 88 0e 49 ff c1 4d 89 ec e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

