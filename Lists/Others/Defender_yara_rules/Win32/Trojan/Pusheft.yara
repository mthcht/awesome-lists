rule Trojan_Win32_Pusheft_A_2147697769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pusheft.A"
        threat_id = "2147697769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pusheft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 67 72 65 65 6e 2f ?? 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_2 = "blancax.dat" ascii //weight: 1
        $x_1_3 = "pussytheft.com" ascii //weight: 1
        $x_1_4 = "(<ip[^>]*>[^<]*</ip>[^<]*<packet" ascii //weight: 1
        $x_2_5 = {89 48 08 8b 55 08 8b 42 04 03 45 a0 89 45 88 8b 4d 88 8a 55 8c 88 11 e9 4b fd ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

