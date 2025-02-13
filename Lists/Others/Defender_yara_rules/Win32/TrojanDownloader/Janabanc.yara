rule TrojanDownloader_Win32_Janabanc_A_2147712911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Janabanc.A"
        threat_id = "2147712911"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Janabanc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TEMP\\pWmlnnoson.exe" wide //weight: 1
        $x_1_2 = "8GFF4XLB7WHM7X7XKLJ3QEYNLGBT4AF2HL7B9H" ascii //weight: 1
        $x_1_3 = "JanelasdoWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Janabanc_B_2147721331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Janabanc.B!bit"
        threat_id = "2147721331"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Janabanc"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JanelasdoWN" ascii //weight: 1
        $x_1_2 = "8GFF4XLB7WHM7X7XKLJ3QEYNLGBT4AF2HL7B9H" ascii //weight: 1
        $x_1_3 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_4 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

