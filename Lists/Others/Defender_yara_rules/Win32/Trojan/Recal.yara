rule Trojan_Win32_Recal_A_2147655779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Recal.A"
        threat_id = "2147655779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Recal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 52 45 43 59 43 4c 45 52 5c 63 (66|74) (66|74) 5f 6d 6f 6e 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\RECYCLER\\desktop.imi" wide //weight: 1
        $x_1_3 = "smile2.log" ascii //weight: 1
        $x_1_4 = "smile.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

