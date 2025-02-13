rule TrojanSpy_Win32_Bebloh_A_2147611308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bebloh.A"
        threat_id = "2147611308"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bebloh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ID=X5CV89BB17LHYT89T0" ascii //weight: 2
        $x_2_2 = {74 68 65 62 61 74 2e 65 78 65 00 00 6d 73 69 6d 6e 2e 65 78 65 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6d 79 69 65 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_4 = {49 63 6f 64 65 65 6e 64 3d 7c 00 00 49 69 6e 6a 65 63 74 3d 7c 00 00 00 49 66 6f 72 6d 3d 7c 00}  //weight: 2, accuracy: High
        $x_1_5 = "ZwWriteVirtualMemory" ascii //weight: 1
        $x_7_6 = {8b fe 03 ff 80 7c fb 08 05 75 6c 8b 44 fb 04 3b 45 f4 75 63 6a 02 6a 00 6a 00 8d 45 ec 50 6a ff 0f b7 44 fb 0a 50}  //weight: 7, accuracy: High
        $x_2_7 = {04 48 4b 45 59 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 48 48 4f 4f 4b 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

