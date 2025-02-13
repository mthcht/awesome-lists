rule Trojan_MSIL_RaspberryRobin_MBEX_2147896691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RaspberryRobin.MBEX!MTB"
        threat_id = "2147896691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaspberryRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 69 02 00 00 95 2e 03 16 2b 01 17 17 59 7e ?? 00 00 04 16 9a 20 71 01 00 00 95 5f 7e 4c 00 00 04 16 9a 20 b5 02 00 00 95 61 58 80 16 00 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = "tractPMAORI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RaspberryRobin_MBEY_2147896692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RaspberryRobin.MBEY!MTB"
        threat_id = "2147896692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaspberryRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 54 13 00 00 95 5f 11 1c 20 af 04 00 00 95 61 59 80 44 00 00 04 38 63 01 00 00 7e 44 00 00 04 11 1c 20 9c 0f 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 b6 0b 00 00 95 5f 7e 37 00 00 04 20 19 0f 00 00 95 61 59 13 3b 38 b8 00 00 00 11 3b 7e 37 00 00 04 20 bb 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_RaspberryRobin_MBEZ_2147896693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RaspberryRobin.MBEZ!MTB"
        threat_id = "2147896693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaspberryRobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 76 6d 63 6f 73 78 66 74 49 34 30 36 2e 64 6c 6c 00 6d 73 63 6f 72 6c 69 62 00 6d 73 6b 65 79 72}  //weight: 1, accuracy: High
        $x_1_2 = {43 49 4d 57 73 6f 66 74 65 41 70 69 74 61 6c 78 00 6e 65 74 62 74 73 67 55 49 47 58 61 6d 6c 4a 50}  //weight: 1, accuracy: High
        $x_1_3 = {73 6b 64 6c 6c 32 45 6e 73 76 63 00 4b 42 44 56 64 65 77 65 72 56 50 53 52 45 53 00 6d}  //weight: 1, accuracy: High
        $x_1_4 = {61 74 69 74 6d 47 57 79 62 45 45 78 66 70 6c 77 66 00 6c 6d 68 73 6e 54 57 73 72 32 63}  //weight: 1, accuracy: High
        $x_1_5 = {61 76 69 66 73 6f 66 74 59 50 6f 77 47 57 4a 00 64 6e 73 6d 6b 57 69 6e 64 6f 77 54 44 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

