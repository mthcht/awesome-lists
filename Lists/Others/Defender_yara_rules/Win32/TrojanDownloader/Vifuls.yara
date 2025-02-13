rule TrojanDownloader_Win32_Vifuls_A_2147685588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vifuls.A"
        threat_id = "2147685588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vifuls"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 74 6d 70 [0-64] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = {73 73 7a 7a 7a [0-64] 4b 42 [0-64] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_3 = {74 65 78 74 2f 68 74 6d 6c [0-2] 2a 2f 2a [0-16] 4d 6f 7a 69 6c 6c 61 2f 33 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 49 6e 64 79 20 4c 69 62 72 61 72 79 29}  //weight: 2, accuracy: Low
        $x_2_4 = "Q0A1815EB2EF2P" ascii //weight: 2
        $x_2_5 = "htpclt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

