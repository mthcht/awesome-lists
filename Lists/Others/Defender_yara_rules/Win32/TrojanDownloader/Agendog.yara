rule TrojanDownloader_Win32_Agendog_A_2147605988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Agendog.A"
        threat_id = "2147605988"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Agendog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\new\\dog\\dog\\pcihdd\\objfre_wxp_x86\\i386\\pcihdd.pdb" ascii //weight: 3
        $x_1_2 = {53 59 53 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 75 73 62 68 64 64 2e 73 79 73}  //weight: 1, accuracy: High
        $x_1_3 = {5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 [0-5] 5c 50 68 79 73 69 63 61 6c 48 61 72 64 44 69 73 6b 30}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f 77 62 2e 78 69 61 7a 61 69 7a 68 65 2e 6e 65 74 2f 6e 2e 65 78 65 00 41 41 41 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

