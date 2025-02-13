rule Trojan_Win64_BeaverTail_RPX_2147896765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BeaverTail.RPX!MTB"
        threat_id = "2147896765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BeaverTail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db 4c 89 65 07 48 8d 45 0f 89 75 ff 48 89 44 24 30 48 8d 4d ff 45 33 c9 89 5c 24 28 45 33 c0 48 89 5c 24 20 33 d2 45 84 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

