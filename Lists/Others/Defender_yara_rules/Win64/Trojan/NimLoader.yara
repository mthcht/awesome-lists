rule Trojan_Win64_NimLoader_RCB_2147909043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NimLoader.RCB!MTB"
        threat_id = "2147909043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NimLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invalid hex char" ascii //weight: 1
        $x_5_2 = {48 8b 54 24 48 48 89 83 68 20 00 00 48 81 83 70 20 00 00 00 10 00 00 48 89 70 10 48 c7 00 e8 0f 00 00 48 c7 40 08 18 00 00 00 48 8b 8b 68 20 00 00 4c 8b 41 08 48 29 11 4e 8d 0c 01 49 01 d0 4c 89 41 08 4c 89 c9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NimLoader_A_2147913505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NimLoader.A!MTB"
        threat_id = "2147913505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NimLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 ?? 49 8b 0c f7 4c 89 f2 48 d3 fa 30 54 18 ?? 48 83 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

