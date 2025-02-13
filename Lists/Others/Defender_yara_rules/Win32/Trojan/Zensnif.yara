rule Trojan_Win32_Zensnif_A_2147828609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zensnif.A"
        threat_id = "2147828609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zensnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 [0-2] 8a 24 0a 28 c4 88}  //weight: 1, accuracy: Low
        $x_10_2 = {66 6a 00 05 ?? ?? 00 00 50 ff 14 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

