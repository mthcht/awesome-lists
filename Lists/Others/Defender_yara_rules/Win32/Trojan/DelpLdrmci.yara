rule Trojan_Win32_DelpLdrmci_A_2147756395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelpLdrmci.A"
        threat_id = "2147756395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelpLdrmci"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 01 00 00 53 6a 00 e8 ?? ?? fa ff 90 e8 ?? ?? fa ff 80 3b 43 75 1f 80 7b 03 53 75 19 80 7b 05 4c 75 13 80 7b 04 45 75 0d 80 7b 06 46 75 07 6a 00 e8 ?? ?? fa ff}  //weight: 2, accuracy: Low
        $x_2_2 = {ba d7 88 00 00 31 c9 80 34 01 ?? 41 39 d1 75 f7 05 4d 32 00 00 ff e0}  //weight: 2, accuracy: Low
        $x_1_3 = "mciSendCommandA" ascii //weight: 1
        $x_1_4 = "FPUMaskValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

