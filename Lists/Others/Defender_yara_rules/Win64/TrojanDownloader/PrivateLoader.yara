rule TrojanDownloader_Win64_PrivateLoader_CAZS_2147845113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/PrivateLoader.CAZS!MTB"
        threat_id = "2147845113"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "PrivateLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 62 7a 2e 62 62 62 65 69 6f 61 61 67 2e 63 6f 6d 2f 73 74 73 2f [0-31] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = "view://Update" wide //weight: 1
        $x_1_3 = "view://DefiniitonUpdate" wide //weight: 1
        $x_1_4 = "%windir%\\hh.exe" wide //weight: 1
        $x_1_5 = "InstallLocation" wide //weight: 1
        $x_1_6 = "SubmitSample" wide //weight: 1
        $x_1_7 = "ScanNow" wide //weight: 1
        $x_1_8 = "CleanSystem" wide //weight: 1
        $x_1_9 = "ShowThreats" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

