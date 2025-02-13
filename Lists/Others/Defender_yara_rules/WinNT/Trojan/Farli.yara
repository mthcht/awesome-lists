rule Trojan_WinNT_Farli_C_2147599144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Farli.C!sys"
        threat_id = "2147599144"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Farli"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c0 85 f6 0f 9d c0 5e c9 c2 04 00}  //weight: 2, accuracy: High
        $x_2_2 = {ab ab ab 8d 45 f4 56 89 45 dc 56 33 c0 8d 7d f0 6a 21 89 75 ec 6a 01 6a 01 ab 68 80 00}  //weight: 2, accuracy: High
        $x_2_3 = {74 4d 8b 46 3c 83 65 08 00 8b 44 30 78 03 c6}  //weight: 2, accuracy: High
        $x_2_4 = {f3 ab 66 ab aa 8d 45 f8 50 8d 45 fc 6a 04 50 6a 0b ff d6 3d 04 00 00 c0}  //weight: 2, accuracy: High
        $x_2_5 = {59 c2 04 00 25 00 73 00 25 00 73 00}  //weight: 2, accuracy: High
        $x_2_6 = {25 00 25 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 25 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 52 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32}  //weight: 2, accuracy: High
        $x_2_7 = "em32\\%s.dll,DllU" wide //weight: 2
        $x_5_8 = "ZwQuerySystemInformation" ascii //weight: 5
        $x_5_9 = "ntoskrnl.exe" ascii //weight: 5
        $x_5_10 = "ZwCreateFile" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 7 of ($x_2_*))) or
            ((3 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

