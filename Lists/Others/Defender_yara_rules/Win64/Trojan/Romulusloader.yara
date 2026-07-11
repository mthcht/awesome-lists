rule Trojan_Win64_Romulusloader_MCT_2147973289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Romulusloader.MCT!MTB"
        threat_id = "2147973289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Romulusloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 6b 45 6e 75 6d 65 72 61 74 65 49 6e 73 74 61 6e 63 65 56 65 72 73 69 6f 6e 00 40 85 03 00 9c b7 78 5e b2 e6 15 23 de 88 03 00 00 60 02 00 b0 86 03 00 36 23 ff 4c df e0 72 02 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

