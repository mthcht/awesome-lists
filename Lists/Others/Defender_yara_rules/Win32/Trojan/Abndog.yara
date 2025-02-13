rule Trojan_Win32_Abndog_A_2147609770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Abndog.A"
        threat_id = "2147609770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Abndog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 38 5b 01 00 52 ff d6 68 c8 49 00 00 ff 15 ?? ?? ?? ?? 8d 44 24 18 45 50 68 ?? ?? ?? ?? 53 83 c7 04}  //weight: 10, accuracy: Low
        $x_1_2 = {48 6f 6f 6b 4c 65 61 76 65 00 00 00 48 6f 6f 6b 45 6e 74 65 72 00 00 00 44 4c 4c 00 48 4f 4f 4b 00 00 00 00 25 73 5c 25 30 38 58 2e 64 6c 6c 00 5f 54 48 49}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\pack_%d.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Abndog_A_2147609770_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Abndog.A"
        threat_id = "2147609770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Abndog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {85 f6 74 37 80 3e 90 75 32 80 7e 01 60 75 2c 80 7e 02 e9 75 26 8b 46 03 8d 44 30 07 8d 70 0a 56 ff d7 84 c0 74 15 80 3e 74 75 10 6a 01 8d 45 ec 50 56}  //weight: 10, accuracy: High
        $x_10_2 = {81 c7 e9 1c 00 00 57 ff d6 84 c0 74 14 80 3f 75 75 0f 6a 01 8d 85 fc fd ff ff 50 57 e8}  //weight: 10, accuracy: High
        $x_1_3 = "\\Device\\NBA_SOFT" wide //weight: 1
        $x_1_4 = "MmIsAddressValid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

