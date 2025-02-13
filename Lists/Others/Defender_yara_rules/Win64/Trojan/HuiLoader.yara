rule Trojan_Win64_HuiLoader_A_2147852041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HuiLoader.A!MTB"
        threat_id = "2147852041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HuiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 ff c3 41 f7 e9 c1 fa ?? 8b c2 c1 e8 1f 03 d0 41 8b c1 41 ff c1}  //weight: 2, accuracy: Low
        $x_2_2 = {2b c2 48 63 c8 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

