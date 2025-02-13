rule TrojanDownloader_Win32_Adodb_A_2147663479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adodb.A"
        threat_id = "2147663479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adodb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paypth =" wide //weight: 1
        $x_1_2 = "lnknme =" wide //weight: 1
        $x_1_3 = "Svr = \"http://" wide //weight: 1
        $x_1_4 = "00002 peelS.tpircsW" wide //weight: 1
        $x_1_5 = "sbv.syrt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

