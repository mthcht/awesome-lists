rule TrojanDownloader_Win32_Strictor_AC_2147900820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Strictor.AC!MTB"
        threat_id = "2147900820"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://180.97.195.146/uploads/" wide //weight: 1
        $x_1_2 = "Desktop\\Sc\\Release\\Sc.pdb" ascii //weight: 1
        $x_1_3 = "Set-Cookie:\\b*{.+" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

