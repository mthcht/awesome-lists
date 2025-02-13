rule Trojan_Win64_SelfDelf_EM_2147847118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SelfDelf.EM!MTB"
        threat_id = "2147847118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SelfDelf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b8 00 00 eb 06 4d 31 d2 4d 31 db 43 8a 04 18 42 30 04 11 49 ff c2 49 ff c3 49 39 d2 74 0d 45 38 cb 74 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

