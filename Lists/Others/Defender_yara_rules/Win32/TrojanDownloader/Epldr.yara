rule TrojanDownloader_Win32_Epldr_A_2147643852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Epldr.A"
        threat_id = "2147643852"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Epldr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_exploit_hosting\\_new2_dwnldr_" wide //weight: 1
        $x_1_2 = {44 6f 77 6e 6c 6f 61 64 50 72 6f 67 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

