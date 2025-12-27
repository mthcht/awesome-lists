rule Trojan_Win64_PipeDown_C_2147957205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PipeDown.C!dha"
        threat_id = "2147957205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PipeDown"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 ?? ?? 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 45 00 64 00 67 00 65 00 5c 00 45 00 64 00 67 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6c 6f 62 61 6c 5c 53 69 6e 67 6c 65 43 6f 72 ?? 6f 72 61 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

