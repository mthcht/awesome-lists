rule Trojan_Win64_DllSideLoad_GVF_2147975994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllSideLoad.GVF!MTB"
        threat_id = "2147975994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllSideLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 38 bc ff ff 40 89 85 38 bc ff ff 0f b7 85 68 bd ff ff 39 85 38 bc ff ff 7d 3b 8b 85 38 bc ff ff 25 7f 00 00 80 79 05 48 83 c8 80 40 0f be 84 05 1c 9c ff ff 8b 8d 30 b7 ff ff 03 8d 38 bc ff ff 0f be 09 33 c8 8b 85 30 b7 ff ff 03 85 38 bc ff ff 88 08 eb a9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

