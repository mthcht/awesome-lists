rule Trojan_Win64_Dapto_A_2147978547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapto.A!MTB"
        threat_id = "2147978547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapto"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 8d 49 fe 41 83 e1 07 47 0f b6 0c 01 44 32 4c 11 fe 44 88 4c 08 fe 44 8d 49 ff 41 83 e1 07 47 0f b6 0c 01 41 89 ca 41 83 e2 07 47 0f b6 14 02 44 32 4c 11 ff 44 32 14 11 44 88 4c 08 ff 44 88 14 08 48 83 c1 03 48 81 f9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

