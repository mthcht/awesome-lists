rule TrojanDownloader_Win32_Deewomz_A_2147647585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Deewomz.A"
        threat_id = "2147647585"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Deewomz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 04 77 83 f0 07 99 b9 7e 00 00 00 f7 f9 66 89 14 73 46 eb cf}  //weight: 2, accuracy: High
        $x_2_2 = {8d 70 01 8a 10 40 84 d2 75 ?? 2b c6 3b c8 73 ?? 0f be 04 39 83 f0 03}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 02 8d 95 98 fa ff ff 52 8d 85 e0 fe ff ff c6 45 fc 06 8b 4d 08 50 51 ff 15}  //weight: 2, accuracy: High
        $x_2_4 = "]jlja{cv" wide //weight: 2
        $x_2_5 = "\\`i{xn}jSBfl}`" wide //weight: 2
        $x_1_6 = "3fbc4b357729c3566c07e16bfc1896d3" ascii //weight: 1
        $x_1_7 = "489503cf7e770d4b143b905b72bb905463c7d99ad134f34fbfd6e4a5435f0f68" ascii //weight: 1
        $x_1_8 = "TlVMTA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

