rule TrojanDownloader_Win32_Pron_XFX_2147621414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pron.XFX"
        threat_id = "2147621414"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*\\AC:\\Documents and Settings\\All Users\\ghijk\\Project1.vbp" wide //weight: 1
        $x_1_2 = "PayTime :" wide //weight: 1
        $x_1_3 = "WScript.Shell" wide //weight: 1
        $x_1_4 = "adult-dougaga.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

