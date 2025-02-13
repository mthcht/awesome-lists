rule TrojanDownloader_Win32_Dabvegi_A_2147628668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dabvegi.A"
        threat_id = "2147628668"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dabvegi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 61 64 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 68 61 6d 61 46 69 72 65 77 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 72 54 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 79 73 66 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

