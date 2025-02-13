rule Trojan_Win32_Karagany_156935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Karagany"
        threat_id = "156935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Karagany"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 03 68 00 00 00 c0 68 ?? ?? ?? ?? ff d7 8b f0 83 fe ff}  //weight: 2, accuracy: Low
        $x_2_2 = {68 02 01 00 00 8d 8d ?? ?? ff ff 51 ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {46 83 fe 14 7c ?? 8b 0d ?? ?? ?? ?? 6a ff 51 ff 15 ?? ?? ?? ?? 68 ff 07 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = "/knock.php" ascii //weight: 1
        $x_1_5 = "geo/productid.php" ascii //weight: 1
        $x_1_6 = "mshta.exe" wide //weight: 1
        $x_1_7 = "\\Adobe\\AdobeUpdate .exe" wide //weight: 1
        $x_1_8 = {64 6f 77 6e 65 78 65 63 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 64 62 55 70 64 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_10 = {78 64 69 65 78 00}  //weight: 1, accuracy: High
        $x_1_11 = "plugin/xgate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

