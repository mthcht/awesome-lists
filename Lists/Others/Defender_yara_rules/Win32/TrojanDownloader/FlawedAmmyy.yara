rule TrojanDownloader_Win32_FlawedAmmyy_A_2147746154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FlawedAmmyy.A!dha"
        threat_id = "2147746154"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft System Protect" wide //weight: 1
        $x_1_2 = "/C net.exe stop foundation" wide //weight: 1
        $x_1_3 = "%s\\AMMYY\\wmihost.exe" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 64 61 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

