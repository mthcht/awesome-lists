rule Trojan_Win32_AMSI_HardwareBreakPoint_2147944491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AMSI.HardwareBreakPoint.MK"
        threat_id = "2147944491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AMSI"
        severity = "Critical"
        info = "MK: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 64 64 56 65 63 74 6f 72 65 64 45 78 63 65 70 74 69 6f 6e 48 61 6e 64 6c 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 58 43 45 50 54 49 4f 4e 5f 42 52 45 41 4b 50 4f 49 4e 54 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {41 4d 53 49 5f 52 45 53 55 4c 54 5f 43 4c 45 41 4e 00}  //weight: 1, accuracy: High
        $n_1_7 = "Windows.Win32.winmd" ascii //weight: -1
        $n_1_8 = "IMetaDataWinMDImport" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

