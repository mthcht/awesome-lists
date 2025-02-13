rule TrojanDownloader_Win32_Bulz_BU_2147889045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bulz.BU!MTB"
        threat_id = "2147889045"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 8d 44 24 10 50 6a 06 56 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 03 6a 00 6a 00 ff b5 c8 fb ff ff 50 57 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "Global\\h48yorbq6rm87zot" wide //weight: 1
        $x_1_4 = "app.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

