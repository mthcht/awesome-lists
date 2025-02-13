rule Trojan_WinNT_Sality_2147626219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sality"
        threat_id = "2147626219"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sality"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Device\\IPFILTERDRIVER" wide //weight: 10
        $x_10_2 = "PsTerminateSystemThread" ascii //weight: 10
        $x_10_3 = {81 e2 ff ff 00 00 83 fa ?? 74 0d 8b 45 ?? 25 ff ff 00 00 83 f8 ?? 75 07 b8 01 00 00 00 eb ?? c7 45 fc 00 00 00 00 eb 09 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc}  //weight: 10, accuracy: Low
        $x_10_4 = {25 ff ff 00 00 25 00 ff 00 00 c1 f8 08 8b 4d 08 81 e1 ff ff 00 00 81 e1 ff 00 00 00 c1 e1 08 0b c1}  //weight: 10, accuracy: High
        $x_1_5 = "kaspersky" ascii //weight: 1
        $x_1_6 = "virustotal." ascii //weight: 1
        $x_1_7 = "sality-remov" ascii //weight: 1
        $x_1_8 = "http://kukutrustnet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

