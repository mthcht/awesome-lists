rule Trojan_Win64_MustangPanda_GVA_2147965623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MustangPanda.GVA!MTB"
        threat_id = "2147965623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 54 00 4d 00 50 00 25 00 [0-60] 2e 00 64 00 6f 00 63 00 78 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

