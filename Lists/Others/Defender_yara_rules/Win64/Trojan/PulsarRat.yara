rule Trojan_Win64_PulsarRat_ARP_2147967042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PulsarRat.ARP!MTB"
        threat_id = "2147967042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PulsarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 9c 24 18 01 00 00 48 8d 15 6e dc 00 00 48 8b c8 48 89 bc 24 10 01 00 00 ff 15 ?? ?? ?? ?? 48 8d 15 66 dc 00 00 49 8b cd 48 8b d8 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 db}  //weight: 2, accuracy: Low
        $x_1_2 = {48 63 ca ff c2 0f be 44 0c 50 66 89 44 4d b0 48 63 c2 40 38 74 04 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

