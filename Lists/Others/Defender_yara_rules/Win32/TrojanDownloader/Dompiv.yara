rule TrojanDownloader_Win32_Dompiv_A_2147628378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dompiv.A"
        threat_id = "2147628378"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dompiv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo s| cacls C:\\WINDOWS\\system32\\drivers\\gbpKm.sys /D TODOS" ascii //weight: 1
        $x_1_2 = "sc STOP GbpKm" ascii //weight: 1
        $x_1_3 = "sc DELETE snmgrsvc" ascii //weight: 1
        $x_1_4 = "sc DELETE snsms" ascii //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 7e 00 76 00 69 00 70 00 6d 00 6f 00 64 00 2f 00 70 00 75 00 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

