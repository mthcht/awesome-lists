rule Trojan_Win32_Doturtix_A_2147697454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doturtix.A"
        threat_id = "2147697454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doturtix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 78 65 63 75 74 65 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 65 74 65 73 65 6c 66 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "aThisDllFile:" ascii //weight: 1
        $x_1_4 = "aExecuteFile:" ascii //weight: 1
        $x_1_5 = "...RUN::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

