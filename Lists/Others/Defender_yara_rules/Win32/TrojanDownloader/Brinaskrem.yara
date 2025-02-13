rule TrojanDownloader_Win32_Brinaskrem_A_2147655852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brinaskrem.A"
        threat_id = "2147655852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brinaskrem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uaq*.dll" ascii //weight: 1
        $x_1_2 = "%c%c%c%c%c.xmp" ascii //weight: 1
        $x_1_3 = {73 75 63 63 00 00 50 72 6f 78 79}  //weight: 1, accuracy: High
        $x_2_4 = {d3 d0 bf a8 b0 cd cb b9 bb f9 a3 ac b2 bb d2 aa b0 f3 b6 a8 73 68 65 6c 6c}  //weight: 2, accuracy: High
        $x_2_5 = {75 0d 8b 6c 24 18 25 ff 0f 00 00 03 c7 01 28 8b 41 04 46 83 e8 08 83 c2 02 d1 e8 3b f0 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

