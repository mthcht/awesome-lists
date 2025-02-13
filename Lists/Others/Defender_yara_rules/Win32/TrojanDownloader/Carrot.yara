rule TrojanDownloader_Win32_Carrot_A_2147765323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Carrot.A!ibt"
        threat_id = "2147765323"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Carrot"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xz.dashi88.com" ascii //weight: 2
        $x_1_2 = "/carrot.ini" ascii //weight: 1
        $x_1_3 = "shortround.pdb" ascii //weight: 1
        $x_1_4 = "sedebugprivilege" ascii //weight: 1
        $x_1_5 = "\\windows\\currentversion\\sontag" ascii //weight: 1
        $x_1_6 = "flowerylife" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

