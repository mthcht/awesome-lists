rule Trojan_Win32_STXRata_BB_2147967770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/STXRata.BB"
        threat_id = "2147967770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "STXRata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 c8 0d 80 f9 61 72}  //weight: 10, accuracy: High
        $x_10_2 = {81 f9 8e 4e 0e ec 74 [0-4] 81 f9 aa fc 0d 7c 74 [0-4] 81 f9 54 ca af 91 74 [0-4] 81 f9 ef ce e0 60 75}  //weight: 10, accuracy: Low
        $x_10_3 = {81 f9 b8 0a 4c 53 74 [0-4] 81 f9 1a 06 7f ff 75}  //weight: 10, accuracy: Low
        $x_10_4 = "InitSecurityInterfaceA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

