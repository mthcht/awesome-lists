rule TrojanDownloader_Win32_Pher_A_2147651243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pher.A"
        threat_id = "2147651243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pher"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks /create /sc onlogon /tn \":schname\" /tr \"\\\":path\"\\\"  :vista" wide //weight: 2
        $x_3_2 = "type_function_deCrypt" ascii //weight: 3
        $x_2_3 = "dwinstallRegsetting" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

