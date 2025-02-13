rule Trojan_Win32_Loasum_A_2147818134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loasum.A"
        threat_id = "2147818134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loasum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 fc 03 c8 0f b6 c9 89 4d fc 8a 04 31 88 04 37 47 88 1c 31 81 ff 00 01 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 04 08 8b 4d 08 32 04 19 88 03 43 83 6d 10 01 8b 45 fc 89 5d 0c 75}  //weight: 10, accuracy: High
        $x_1_3 = {6a 64 6a 00 ff [0-5] 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_4 = {55 4e 4b 4e 4f 57 4e 44 4c 4c 2e 44 4c 4c 00 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 41 50 49}  //weight: 1, accuracy: High
        $x_1_5 = "networkexplorer.DLL" ascii //weight: 1
        $x_1_6 = "NlsData0000.DLL" ascii //weight: 1
        $x_1_7 = "NetProjW.DLL" ascii //weight: 1
        $x_1_8 = "Ghofr.DLL" ascii //weight: 1
        $x_1_9 = "fg122.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

