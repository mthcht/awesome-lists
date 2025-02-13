rule Trojan_Win32_Cadux_C_2147615104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cadux.C"
        threat_id = "2147615104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 00 3a 00 5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 62 00 62 00 5f 00 73 00 6f 00 66 00 74 00 5c 00 6e 00 5f 00 30 00 37 00 5f 00 31 00 30 00 5f 00 32 00 30 00 30 00 38 00 5c 00 62 00 62 00 5f 00 62 00 68 00 6f 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {44 3a 5c 4d 61 73 74 65 72 5c 55 4e 49 5f 53 4f 46 54 5c 41 44 57 41 52 41 5c 62 68 6f 5c 76 62 62 68 6f 2e 74 6c 62 00}  //weight: 10, accuracy: High
        $x_1_3 = {67 65 74 73 6e 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cadux_C_2147615104_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cadux.C"
        threat_id = "2147615104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\Master\\bb_soft\\n_07_10_2008\\dll.vbp" wide //weight: 10
        $x_10_2 = "D:\\Master\\bb_soft\\new\\dll.vbp" wide //weight: 10
        $x_10_3 = "D:\\Master\\bb_soft\\not_est\\dll.vbp" wide //weight: 10
        $x_10_4 = "D:\\Master\\bb_soft\\n_13_10_2008\\dll.vbp" wide //weight: 10
        $x_1_5 = "smwin32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

