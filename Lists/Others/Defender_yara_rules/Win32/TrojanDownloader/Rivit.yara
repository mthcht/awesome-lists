rule TrojanDownloader_Win32_Rivit_A_2147720911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rivit.A!dha"
        threat_id = "2147720911"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rivit"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gnip c/ exe.dmc" ascii //weight: 1
        $x_1_2 = "c- neddih w- pon- exe.llehsrewop" ascii //weight: 1
        $x_1_3 = "//:ptth'(gnirtsdaolnwod.J$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

