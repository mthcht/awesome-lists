rule Trojan_Win64_OrcusRAT_A_2147918884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OrcusRAT.A!MTB"
        threat_id = "2147918884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OrcusRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 41 f1 30 04 39 48 ff c1 48 81 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

