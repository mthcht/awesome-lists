rule Trojan_Win64_Sysn_AB_2147978626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sysn.AB!MTB"
        threat_id = "2147978626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sysn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 c9 41 83 e1 0f 47 8a 0c 01 41 30 c9 44 30 0c 08 48 ff c1 48 39 ca 75}  //weight: 5, accuracy: High
        $x_5_2 = {46 8a 8c 04 ?? ?? ?? ?? 47 8d 14 03 46 30 0c 11 49 ff c0 4c 39 c6 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

