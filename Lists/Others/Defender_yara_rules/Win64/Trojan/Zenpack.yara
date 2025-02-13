rule Trojan_Win64_Zenpack_EM_2147898411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zenpack.EM!MTB"
        threat_id = "2147898411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zenpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8d 7d c8 f2 ae 48 f7 d1 48 ff c9 48 63 f9 8b c1 99 2b c2 d1 f8 85 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

