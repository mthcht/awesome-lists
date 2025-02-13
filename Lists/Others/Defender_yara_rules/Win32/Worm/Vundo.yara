rule Worm_Win32_Vundo_A_2147624092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vundo.A"
        threat_id = "2147624092"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 06 6a 04 8d 45 ?? 50 6a 01 68 00 00 00 c0 8d 85 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 06 66 3d 41 00 74 24 66 3d 61 00 74 1e 66 3d 42 00 74 18 66 3d 62 00 74 12 66 3b 45 f4 74 0c 56 ff 15 ?? ?? ?? ?? 83 f8 03 74}  //weight: 1, accuracy: Low
        $x_1_3 = "GetDriveTypeW" ascii //weight: 1
        $x_1_4 = "LoadAppInit_DLLs" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Security Center" wide //weight: 1
        $x_1_6 = "DnsRecordListFree" ascii //weight: 1
        $x_1_7 = "form/index.html" ascii //weight: 1
        $x_1_8 = "Mozilla/4.0 (compatible; MSIE 6.0)" ascii //weight: 1
        $x_1_9 = {50 00 68 00 69 00 73 00 68 00 69 00 6e 00 67 00 46 00 69 00 6c 00 74 00 65 00 72 00 00 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Vundo_B_2147628135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vundo.B"
        threat_id = "2147628135"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 72 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-128] 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 [0-128] 6f 00 70 00 65 00 72 00 61 00 2e 00 65 00 78 00 65 00 [0-128] 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = "Software\\Microsoft\\Security Center" wide //weight: 10
        $x_10_3 = "\\Internet Explorer\\PhishingFilter" wide //weight: 10
        $x_10_4 = "LoadAppInit_DLLs" wide //weight: 10
        $x_2_5 = {0f b7 06 66 83 f8 41 74 ?? 66 83 f8 61 74 ?? 66 83 f8 42 74 ?? 66 83 f8 62 74 ?? 66 3b 45 f4 74 ?? 56 ff 15 ?? ?? ?? ?? 83 f8 03 74}  //weight: 2, accuracy: Low
        $x_1_6 = "form/index.html" ascii //weight: 1
        $x_1_7 = "Global\\" ascii //weight: 1
        $x_1_8 = "85.12.43.102" ascii //weight: 1
        $x_1_9 = "exficale.com" ascii //weight: 1
        $x_1_10 = "pancolp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

