rule TrojanDownloader_Java_NazDown_B_2147762423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/NazDown.B!MTB"
        threat_id = "2147762423"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "NazDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 52 75 6e 74 69 6d 65 [0-50] 2e 63 6f 6d 2f 6e 61 7a 69 6f 6e 61 6c 65 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 61 7a 69 6f 6e 61 6c 65 2e 65 78 65 01 00 04 6f 70 65 6e}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 61 64 01 00 25 72 75 6e 64 6c 6c 33 32 20 75 72 6c 2e 64 6c 6c 2c 46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "Previdenza" ascii //weight: 1
        $x_1_5 = {2f 68 6f 6d 65 2e 68 74 6d 01 00 0e 6a 61 76 61 2e 69 6f 2e 74 6d 70 64 69 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

