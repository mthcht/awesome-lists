rule Trojan_Win64_Palevo_GV_2147977622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Palevo.GV!MTB"
        threat_id = "2147977622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Palevo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 18 80 f1 98 88 0c 18 40 3b c5 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Micropoint\\Anti-Attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

