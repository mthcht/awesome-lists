rule TrojanDownloader_Win32_Wrokni_A_2147735109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wrokni.A!!Wrokni.A"
        threat_id = "2147735109"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wrokni"
        severity = "Critical"
        info = "Wrokni: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "can't load the buf1" ascii //weight: 2
        $x_1_2 = "[dl] down allpath =" ascii //weight: 1
        $x_1_3 = "[dl] shell ret =" ascii //weight: 1
        $x_1_4 = "[dl] url =" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 00 2e 6f 6e 6c 69 6e 65 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

