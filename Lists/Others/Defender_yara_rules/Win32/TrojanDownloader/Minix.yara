rule TrojanDownloader_Win32_Minix_A_2147653658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Minix.A"
        threat_id = "2147653658"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 78 69 78 69 68 61 63 68 65 2e 69 6e 66 6f 3a 31 33 35 35 2f 73 6f 66 74 2f [0-10] 2e 65 78 65 00 2f 53 49 4c 45 4e 54 00 67 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Minix_GXZ_2147908636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Minix.GXZ!MTB"
        threat_id = "2147908636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Minix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Frafaldne Dippens.exe" ascii //weight: 1
        $x_1_2 = "Kartoteksoplysningers" ascii //weight: 1
        $x_1_3 = "Cykelbanes Glossingly Beslime" ascii //weight: 1
        $x_1_4 = "ShellExecuteEx" ascii //weight: 1
        $x_1_5 = "Nonretardative Storrygeren Amaroid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

