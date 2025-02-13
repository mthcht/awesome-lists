rule Worm_Win32_Archivarius_2147602078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Archivarius"
        threat_id = "2147602078"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Archivarius"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "333"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Toolhelp32ReadProcessMemory" ascii //weight: 100
        $x_100_2 = "CreateToolhelp32Snapshot" ascii //weight: 100
        $x_100_3 = "SOFTWARE\\Borland\\Delphi" ascii //weight: 100
        $x_3_4 = "emule.exe" ascii //weight: 3
        $x_3_5 = "LimeWire.exe" ascii //weight: 3
        $x_3_6 = "edonkey.exe" ascii //weight: 3
        $x_3_7 = "Warez.exe" ascii //weight: 3
        $x_3_8 = "\\eDonkey2000 Downloads\\" ascii //weight: 3
        $x_10_9 = {74 65 6d 70 5f 30 31 2e 65 78 65 00 ff ff ff ff 04 00 00 00 54 45 58 54 00 00 00 00 74 65 6d 70 5f 30 31 2e 65 78 65 00 6f 70 65 6e 00 00 00 00 ff ff ff ff 07 00 00 00 72 61 72 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_10 = {42 65 61 72 53 68 61 72 65 2e 65 78 65 00 00 00 ff ff ff ff 0d 00 00 00 6b 61 7a 61 61 6c 69 74 65 2e 6b 70 70 00 00 00 ff ff ff ff 09 00 00 00 6b 61 7a 61 61 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_11 = {83 c9 ff 83 ca ff e8 01 00 00 00 c3 6a 00 52 51 b2 04 66 8b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 2 of ($x_10_*) and 5 of ($x_3_*))) or
            ((3 of ($x_100_*) and 3 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

