rule Trojan_Win64_CodosoGhost_SX_2147974132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CodosoGhost.SX!MTB"
        threat_id = "2147974132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CodosoGhost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 8d 53 0c 41 b8 c0 06 00 00 48 8b ce e8 ?? ?? ?? ?? 48 8d 8c 24 41 01 00 00 33 d2 41 b8 03 01 00 00 40 88 bc 24 40 01 00 00 e8 ?? ?? ?? ?? 44 8b 4c 24 24 4c 8d 05 ?? ?? ?? ?? 48 8d 8c 24 40 01 00 00 41 81 f1 09 06 86 19 ba 04 01 00 00 e8}  //weight: 30, accuracy: Low
        $x_5_2 = "\\\\.\\fstab" wide //weight: 5
        $x_5_3 = "Global\\036DB24B-EDB4-48d0-AC37-F7DA9E1740A9" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

