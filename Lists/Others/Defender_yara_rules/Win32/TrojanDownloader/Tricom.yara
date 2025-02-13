rule TrojanDownloader_Win32_Tricom_A_2147722749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tricom.A!bit"
        threat_id = "2147722749"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tricom"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://lapapahoster.com/safe_download/" wide //weight: 2
        $x_1_2 = "AdsShow.exe" wide //weight: 1
        $x_1_3 = "WCmouiTri.exe" wide //weight: 1
        $x_1_4 = "\\Release\\WCmouiTri.pdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

