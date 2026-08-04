rule Trojan_Win64_BlassultLoader_BB_2147975179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlassultLoader.BB"
        threat_id = "2147975179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlassultLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Dev\\sumatrapdf" ascii //weight: 10
        $x_10_2 = {48 05 fc 76 05 00}  //weight: 10, accuracy: High
        $x_10_3 = {48 05 38 79 05 00}  //weight: 10, accuracy: High
        $x_10_4 = {3c 7f 77 04 8b d9 eb 29 3c bf 77 0e 8b c3 83 e1 3f c1 e0 06 8b d9 0b d8 eb 17 8b d9 3c df 77 05 83 e3 1f eb 0c}  //weight: 10, accuracy: High
        $x_10_5 = "SuspendThread" ascii //weight: 10
        $x_10_6 = {01 00 10 00 04 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

