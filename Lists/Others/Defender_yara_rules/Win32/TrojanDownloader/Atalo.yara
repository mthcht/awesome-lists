rule TrojanDownloader_Win32_Atalo_A_2147654521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Atalo.A"
        threat_id = "2147654521"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Atalo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 52 51 55 49 56 4f 20 4f 4b 5d ?? ?? 50 52 49 4e 43 3d [0-66] 53 45 43 3d [0-66] 44 4c 4c 3d [0-66] 41 56 56 3d [0-66] 4d 53 4e 3d [0-66] 50 4c 55 47 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "If exist \"%s\" Goto 1" ascii //weight: 1
        $x_1_3 = {61 60 53 61 5e 52 5f 58 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 28 bb 01 00 00 00 8d 45 f0 8b 55 fc 0f b6 54 1a ff 2b d3 2b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

