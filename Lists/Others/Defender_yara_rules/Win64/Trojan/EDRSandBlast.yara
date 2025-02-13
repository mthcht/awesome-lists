rule Trojan_Win64_EDRSandBlast_YBJ_2147912647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EDRSandBlast.YBJ!MTB"
        threat_id = "2147912647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRSandBlast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 d0 4d 8d 49 02 66 83 e8 61 66 83 f8 19 8d 4a 20 0f 47 d1 69 c2 93 01 00 01 44 33 c0 41 0f b7 01 66 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {b9 01 00 00 00 ff 15 71 fc 01 00 ff c3 83 fb ff 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

