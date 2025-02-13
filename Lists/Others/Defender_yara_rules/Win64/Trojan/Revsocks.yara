rule Trojan_Win64_Revsocks_FEM_2147920135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Revsocks.FEM!MTB"
        threat_id = "2147920135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Revsocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 c0 e8 04 45 0f b6 c0 4c 8d 15 f8 8e 0c 00 47 0f b6 04 02 48 39 df 73 3a 44 88 04 38 4c 8d 47 01 41 83 e1 0f 47 0f b6 0c 11 4c 39 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

