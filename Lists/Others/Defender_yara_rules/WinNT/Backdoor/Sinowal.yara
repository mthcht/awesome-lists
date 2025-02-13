rule Backdoor_WinNT_Sinowal_A_2147621412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Sinowal.A"
        threat_id = "2147621412"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ObOpenObjectByName" ascii //weight: 1
        $x_1_2 = {2e a1 34 f0 df ff 0b c0 74 ?? 8b 40 70}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 45 fc 83 7d fc 25 72 ?? be 01 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 40 10 03 c7 eb 02 33 c0 3b c6 74 ?? ff 75 08 ff 75 ?? 57 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

