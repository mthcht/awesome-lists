rule Trojan_Win64_SandCat_RTS_2147926848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SandCat.RTS!MTB"
        threat_id = "2147926848"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SandCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reached beacon failure threshold" ascii //weight: 1
        $x_2_2 = "Terminating Sandcat Agent... goodbye" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

