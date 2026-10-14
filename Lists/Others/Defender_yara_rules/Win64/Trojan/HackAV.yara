rule Trojan_Win64_HackAV_HA_2147980259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HackAV.HA!MTB"
        threat_id = "2147980259"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HackAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://47.108.48.69:4044/eupo/info.txt" ascii //weight: 3
        $x_5_2 = {79 00 7a 00 74 00 63 00 73 00 6e 00 0a 00 d1 53 b0 73 b0 65 48 72 2c 67 0c ff 2f 66 26 54 cb 7a 73 53 f4 66 b0 65 1f ff 0a 00 08 ff f4 66 b0 65 0e 54 2c 67 0b 7a 8f 5e 06 5c cd 91 2f 54 76 5e 53 62 00 5f f4 8b 0e 66 75 98 09 ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

