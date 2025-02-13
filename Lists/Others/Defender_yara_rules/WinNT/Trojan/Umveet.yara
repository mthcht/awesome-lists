rule Trojan_WinNT_Umveet_A_2147629520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Umveet.gen!A"
        threat_id = "2147629520"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Umveet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 08 7c e0 68 9d 8f a0 c3 56 07 00 47 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

