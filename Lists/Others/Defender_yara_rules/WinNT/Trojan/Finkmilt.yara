rule Trojan_WinNT_Finkmilt_A_2147643116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Finkmilt.gen!A"
        threat_id = "2147643116"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Finkmilt"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 c7 46 08 73 00 15 00 66 c7 46 08 ?? 00 38 1d ?? ?? ?? ?? 74 ?? 57 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {72 f0 8d 85 7c ff ff ff 50 8d 45 cc}  //weight: 1, accuracy: High
        $x_1_3 = {72 f5 8d 85 60 ff ff ff 50 8d 85 2c ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = "LeTerviceEescriq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

