rule Trojan_Win64_Babuk_NB_2147951477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Babuk.NB!MTB"
        threat_id = "2147951477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 41 3b 11 41 8d 40 01 0f b7 51 02 41 0f 44 c0 48 83 c1 02 49 83 c1 02 44 8b c0 66 83 fa 3d 75 df}  //weight: 2, accuracy: High
        $x_1_2 = {48 63 85 b8 00 00 00 46 88 2c 20 8b 85 b8 00 00 00 ff c0 89 85 b8 00 00 00 48 63 85 b8 00 00 00 49 3b c0 72 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

