rule Trojan_Win64_Riffdell_2147912111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Riffdell"
        threat_id = "2147912111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Riffdell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 01 11 0f 01 59 0a 0f 00 51 14 48 8d 15 ?? ?? ?? ?? 48 0f b7 41 16 50 52 48 cb}  //weight: 1, accuracy: Low
        $x_1_2 = {8e 59 18 8e 41 1a 8e 61 1c 8e 69 1e 8e 51 20 c3}  //weight: 1, accuracy: High
        $x_1_3 = {40 53 48 83 ec 20 8b 51 30 44 8b 41 34 48 8b 5c 0a 10 48 8b 44 0a 1c 0f 22 d8 44 2b c2 41 83 f8 38 74 10 48 83 c1 24 48 8d 05 a2 ff ff ff 48 03 ca ff d0}  //weight: 1, accuracy: High
        $x_10_4 = "67bee8b8-6886-4e85-b5dc-3421b4c4df92" ascii //weight: 10
        $x_10_5 = "cba29ddb-ebe6-4d56-9b84-42fcf8adeaeb" ascii //weight: 10
        $x_10_6 = "e3d7a8ee-4fe3-470f-a62f-074e8e360082" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

