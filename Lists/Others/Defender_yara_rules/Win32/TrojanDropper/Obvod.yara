rule TrojanDropper_Win32_Obvod_A_2147616235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Obvod.A"
        threat_id = "2147616235"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Obvod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c3 85 db 74 0d 6a 02 6a 00 6a 00 56 ff 15 ?? ?? 40 00 8b 5c 24 1c 8b 54 24 18 8d 4c 24 20 6a 00}  //weight: 5, accuracy: Low
        $x_5_2 = {32 da 40 3b c6 88 19 7c e6 5b}  //weight: 5, accuracy: High
        $x_6_3 = {ff d7 6a 00 8d 54 24 6c 68 ?? ?? 40 00 52 e8 ?? ?? ff ff 8b 44 24 18 6a 00 50 8d 4c 24 7c 56 51 e8}  //weight: 6, accuracy: Low
        $x_1_4 = "%s{%s}" ascii //weight: 1
        $x_1_5 = "/s /i %s" ascii //weight: 1
        $x_1_6 = {6e 75 6c 00 00 20 2f 63 20 64 65 6c 20 00}  //weight: 1, accuracy: High
        $x_1_7 = "collect/b.php/%d/%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

