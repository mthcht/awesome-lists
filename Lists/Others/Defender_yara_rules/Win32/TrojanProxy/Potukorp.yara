rule TrojanProxy_Win32_Potukorp_D_2147709725_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Potukorp.D"
        threat_id = "2147709725"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Potukorp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "cmd.exe /c ipconfig /flushdns" ascii //weight: 2
        $x_1_2 = {4d 65 6d 44 6c 6c 2e 64 6c 6c 00 4b 69 65 73 73 00 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 6f 66 66 6c 69 6e 65 5d 00 5b 44 6e 73 5d 00 5b 48 6f 73 74 5d 00 5b 55 70 6c 6f 61 64 5d 00 5b 43 6f 75 6e 74 5d 00 5b 54 69 6d 65 5d}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 00 2a 00 2a 2e 64 65 72 00 2a 2e 63 65 72}  //weight: 1, accuracy: High
        $x_1_5 = "=?0E040A1E43141E1C0806021D055A1B5E" ascii //weight: 1
        $x_1_6 = "1C051C5C181A021C0313055C081D06514F0" ascii //weight: 1
        $x_1_7 = {68 01 03 00 80 6a 00 68 05 00 00 00 68 01 03 00 80 6a 00 68 ?? 00 00 00 68 02 00 00 00 bb cc 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

