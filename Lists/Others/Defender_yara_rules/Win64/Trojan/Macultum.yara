rule Trojan_Win64_Macultum_B_2147684936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Macultum.B"
        threat_id = "2147684936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Macultum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 4d 00 75 00 74 00 75 00 61 00 6c 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "Lua_Helper Bootstrap Downloaded" wide //weight: 1
        $x_1_3 = "Helper - ExecuteProgram adjust privileges" wide //weight: 1
        $x_1_4 = {70 72 6f 6a 65 63 74 73 5c 70 78 5c 6d 6f 6e 69 74 6f 72 5c 4d 6f 6e 69 74 6f 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 26 63 3d 00 26 65 3d 00 26 67 3d 00 3f 76 3d 32 26 6b 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 [0-8] 4d 75 74 75 61 6c 20 69 6e 73 74 61 6c 6c 20 7c 20 72 65 6d 6f 76 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

