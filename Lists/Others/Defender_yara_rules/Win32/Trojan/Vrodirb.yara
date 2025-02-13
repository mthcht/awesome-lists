rule Trojan_Win32_Vrodirb_B_2147654078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vrodirb.B"
        threat_id = "2147654078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vrodirb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 04 8b 54 24 08 f7 40 04 06 00 00 00 74 ?? 8b 4a 04 c7 42 04 ?? ?? 40 00 53 56 57 55 8b 6a 08 83 c1 05 e8 ?? ?? ff ff ff d1}  //weight: 2, accuracy: Low
        $x_1_2 = {2f 3f 44 6c 6c [0-4] 49 45 46 72 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_3 = {42 52 5f 46 52 41 4d 45 [0-4] 58 41 64 64 72 42 61 72}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 4e [0-4] 5c 63 74 66 6d 6f 6e 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "usp10.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

