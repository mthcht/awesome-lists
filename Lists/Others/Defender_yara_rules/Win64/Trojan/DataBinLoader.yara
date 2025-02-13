rule Trojan_Win64_DataBinLoader_A_2147895346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DataBinLoader.A"
        threat_id = "2147895346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DataBinLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 61 74 61 20 66 69 6c 65 20 6c 6f 61 64 65 64 2e 20 52 75 6e 6e 69 6e 67 2e 2e 2e 0a}  //weight: 1, accuracy: High
        $x_1_2 = {4e 6f 20 6b 65 79 20 69 6e 20 61 72 67 73 21 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

