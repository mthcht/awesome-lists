rule Trojan_Win32_BrobanAda_A_2147688034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanAda.A"
        threat_id = "2147688034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanAda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 76 69 73 6f 2e 74 78 74 00 00 00 ff ff ff ff ?? 00 00 00 36 38 37 34 37 34 37 30 33 41 32 46}  //weight: 1, accuracy: Low
        $x_1_2 = {45 78 70 6c 6f 72 65 72 00 00 00 00 ff ff ff ff ?? 00 00 00 [0-15] 32 46 34 31 32 46 36 32 36 46 36 43 36 35 37 34 36 46 32 45 37 30 36 38 37 30 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 35 36 65 36 33 36 66 36 34 36 35 36 34 00 00 ff ff ff ff 02 00 00 00 4f 3d 00 00 ff ff ff ff 03 00 00 00 26 4e 3d 00 ff ff ff ff 03 00 00 00 26 55 3d 00 ff ff ff ff 03 00 00 00 26 56 3d 00 ff ff ff ff 03 00 00 00 26 50 3d 00 ff ff ff ff 03 00 00 00 26 5a 3d 00 ff ff ff ff 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "706C7567696E6368726F6D652E7A6970" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

