rule Trojan_Win64_Shadowladder_GVA_2147962922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shadowladder.GVA!MTB"
        threat_id = "2147962922"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shadowladder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-s -w -H=windowsgui -X" ascii //weight: 1
        $x_2_2 = {3a 2f 2f 31 39 36 2e 32 35 31 2e 31 30 37 2e 31 30 39 2f [0-32] 2e 70 68 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

