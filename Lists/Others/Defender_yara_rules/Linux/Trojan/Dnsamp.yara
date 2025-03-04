rule Trojan_Linux_Dnsamp_A_2147784137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Dnsamp.A!MTB"
        threat_id = "2147784137"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Dnsamp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 40 01 00 e8 ?? ?? ?? ?? 89 c2 48 8b 45 f0 66 89 50 04 48 8b 45 f0 66 c7 40 02 00 00 48 8b 45 f0 66 c7 40 06 00 00 48 8b 85 e8 fe ff ff 48 83 c0 10 48 89 45 f8 48 8d 85 f0 fe ff ff c7 00 b0 a1 b0 a1 c7 40 04 b0 a1 b0 a1 66 c7 40 08 b0 a1 c6 40 0a 00 48 8d 85 f0 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e5 48 81 ec 00 04 00 00 48 c7 85 20 fc ff ff 64 00 00 00 48 c7 85 28 fc ff ff 00 00 00 00 c6 05 24 53 22 00 00 bf 00 a3 02 00 e8 d2 dd ff ff 48 c7 85 18 fe ff ff 01 00 00 00 c6 85 10 fc ff ff 77 c6 85 11 fc ff ff 77 c6 85 12 fc ff ff 77 c6 85 13 fc ff ff 2e c6 85 14 fc ff ff 79 c6 85 15 fc ff ff 67 c6 85 16 fc ff ff 78 c6 85 17 fc ff ff 35 c6 85 18 fc ff ff 2e c6 85 19 fc ff ff 63 c6 85 1a fc ff ff 6f c6 85 1b fc ff ff 6d c6 85 1c fc ff ff 00 c7 45 ec 26 23 00 00}  //weight: 1, accuracy: High
        $x_2_3 = "dosset.dtdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

