rule Trojan_Win32_Fosdimine_A_2147656625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fosdimine.A"
        threat_id = "2147656625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fosdimine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "execminners" ascii //weight: 1
        $x_1_2 = "-u jodyfoster" wide //weight: 1
        $x_1_3 = "bitcoin\\autostart.vbp" wide //weight: 1
        $x_1_4 = "miner\\autostart.vbp" wide //weight: 1
        $x_1_5 = {63 6f 6e 66 69 67 6d 6f 64 [0-4] 64 65 74 65 63 74 6d 6f 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

