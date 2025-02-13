rule Trojan_Win32_Shetwirl_A_2147638945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shetwirl.A"
        threat_id = "2147638945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shetwirl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 00 02 00 00 56 8d 85 ?? ?? ff ff 50 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 0f 84 28 02 00 00 b8 55 aa 00 00 66 39 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 8d 0c 02 8b 01 8b f0 c1 e6 19 c1 e8 07 03 f0 81 f6 ?? ?? ?? ?? 83 c2 04 3b 55 0c 89 31 7c de}  //weight: 2, accuracy: Low
        $x_1_3 = "\\\\.\\PhysicalDrive%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

