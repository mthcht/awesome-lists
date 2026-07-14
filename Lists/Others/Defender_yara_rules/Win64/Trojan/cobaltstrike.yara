rule Trojan_Win64_cobaltstrike_IDK_2147973377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/cobaltstrike.IDK!MTB"
        threat_id = "2147973377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8a 04 10 34 1b 41 88 00 49 ff c0 49 83 e9 01 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

