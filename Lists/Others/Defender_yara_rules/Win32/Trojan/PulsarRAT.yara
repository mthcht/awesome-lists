rule Trojan_Win32_PulsarRAT_PGPR_2147966413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PulsarRAT.PGPR!MTB"
        threat_id = "2147966413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PulsarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 8b 4d 08 01 c1 8b 45 fc 8b 55 08 01 c2 0f be 02 40 83 f0 69 88 01 eb da}  //weight: 5, accuracy: High
        $x_5_2 = {41 50 50 44 41 54 41 00 5c 4d 69 63 72 6f 73 6f 66 74 5c 55 70 64 61 74 65 2e 63 70 6c 00 46 49 4c 45 52 45 53 5f 30 00 25 73 5c [0-31] 2e 65 78 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

