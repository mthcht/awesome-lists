rule TrojanDownloader_Win32_Wangbrax_B_2147693861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wangbrax.B"
        threat_id = "2147693861"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wangbrax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2e 00 6e 00 69 00 74 00 72 00 61 00 64 00 6f 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 64 00 64 00 6f 00 6e 00 73 00 2f 00 [0-2] 6d 00 6d 00 [0-4] 2e 00 65 00 78 00 65 00}  //weight: 4, accuracy: Low
        $x_2_2 = "ni47282_1.vweb10." wide //weight: 2
        $x_2_3 = "flubaf0a9.exe" ascii //weight: 2
        $x_2_4 = {67 65 74 5f 4e 65 74 77 6f 72 6b 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65}  //weight: 2, accuracy: High
        $x_2_5 = "vweb10.nitrado.net/addons" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

