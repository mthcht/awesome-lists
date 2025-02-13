rule Trojan_Win64_RootTeam_RDA_2147850790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RootTeam.RDA!MTB"
        threat_id = "2147850790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RootTeam"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e9 26 00 00 00 c8 25 92 29 7f 21 7e 0c 1e a5 0b 57 ae e9 a8 8a 39 1a d8 ea 82 45 89 83 f3 77 a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

