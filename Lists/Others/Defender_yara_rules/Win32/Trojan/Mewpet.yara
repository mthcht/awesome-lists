rule Trojan_Win32_Mewpet_A_2147652560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mewpet.gen!A"
        threat_id = "2147652560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mewpet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 18 ff 53 34 a1 ?? ?? ?? ?? 8b 00 8b 10 ff 52 3c 33 c0 5a 59 59}  //weight: 2, accuracy: Low
        $x_1_2 = {70 74 6d 70 32 (64|68) 5f 73 76 63}  //weight: 1, accuracy: Low
        $x_1_3 = "?cpu=%5.2f&mem=%5.2f&p=%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

