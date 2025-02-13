rule Trojan_WinNT_Ramnit_A_2147645307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Ramnit.gen!A"
        threat_id = "2147645307"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Ramnit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "demetra\\loader" ascii //weight: 3
        $x_2_2 = "hVrl " ascii //weight: 2
        $x_2_3 = {0f b7 02 3d 4d 5a 00 00 75 02 eb 14 8b 0d}  //weight: 2, accuracy: High
        $x_2_4 = {bf 22 00 00 c0 8b c6 41 f0 0f c1 08 8d 45 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

