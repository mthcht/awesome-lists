rule TrojanDownloader_Win32_Hitpop_A_2147602918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hitpop.A"
        threat_id = "2147602918"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c3 3d 60 ea 00 00 72 ?? e8 ?? ?? ?? ?? 8b [0-6] 50 8d 45 ec 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8}  //weight: 1, accuracy: Low
        $x_1_2 = "del %0" ascii //weight: 1
        $x_1_3 = "hitpop" ascii //weight: 1
        $x_1_4 = "AVP.Button" ascii //weight: 1
        $x_1_5 = "AVP.AlertDialog" ascii //weight: 1
        $x_1_6 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_7 = "AVP.TrafficMonConnectionTerm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

