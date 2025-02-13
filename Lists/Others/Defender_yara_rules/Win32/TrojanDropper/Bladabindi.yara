rule TrojanDropper_Win32_Bladabindi_BI_2147725116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bladabindi.BI!bit"
        threat_id = "2147725116"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 44 6f 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 [0-16] 2e 73 65 6e 64 6b 65 79 73 22 7b 6e 75 6d 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 [0-16] 2e 73 65 6e 64 6b 65 79 73 22 7b 63 61 70 73 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 20 [0-16] 2e 73 65 6e 64 6b 65 79 73 22 7b 73 63 72 6f 6c 6c 6c 6f 63 6b 7d 22 0d 0a 57 53 63 72 69 70 74 2e 73 6c 65 65 70 [0-8] 4c 6f 6f 70}  //weight: 1, accuracy: Low
        $x_1_2 = "Server.sfx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

