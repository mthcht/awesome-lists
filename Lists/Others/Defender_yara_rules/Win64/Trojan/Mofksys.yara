rule Trojan_Win64_Mofksys_ARA_2147963819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mofksys.ARA!MTB"
        threat_id = "2147963819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f b6 0f 41 80 f1 55 48 8b 4b 10 48 8b 53 18 48 3b ca 73 1f 48 8d 41 01 48 89 43 10 48 8b c3 48 83 fa ?? ?? 03 48 8b 03 44 88 0c 08 c6 44 08 01 00 eb 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

