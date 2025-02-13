rule Trojan_Win32_Musomar_A_2147606852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Musomar.A"
        threat_id = "2147606852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Musomar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 2b 80 00 00 6a 00 ff 15 ?? ?? ?? 00 85 c0 7c ?? 8d ?? ec fc ff ff ?? 68 ?? ?? ?? 00 68 04 01 00 00 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {aa 68 95 00 00 00 8d ?? 68 ff ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {83 bd 78 ff ff ff 05 73 2a 8b 8d 78 ff ff ff 8b 94 8d 64 ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = "phobos.name" ascii //weight: 1
        $x_1_5 = "drvrsc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

