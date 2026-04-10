rule Trojan_Win64_Adaptagent_VGY_2147966617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Adaptagent.VGY!MTB"
        threat_id = "2147966617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Adaptagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 89 f3 89 de 0f af f2 01 c6 83 fe 01 0f 8e 3f 01 00 00 c1 e6 02 48 63 f6 41 0f b6 1c 33 88 5c 24 59 41 8d 58 01 39 cb 0f 83 6c 01 00 00 41 0f b6 5c 33 01 88 5c 24 5a 41 8d 58 02 39 cb 0f 83 5c 02 00 00 41 0f b6 5c 33 02}  //weight: 2, accuracy: High
        $x_1_2 = {0f b6 43 01 48 83 c3 02 88 44 24 70 4c 39 e3 0f 84 35 01 00 00 0f b6 03 48 83 c3 01 41 b9 02 00 00 00 88 44 24 71 4c 39 e3 74 24 0f b6 03 41 8d 79 01 42 88 44 0c 70 81 ff ff 0f 00 00 0f 87 67 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

