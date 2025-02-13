rule TrojanDownloader_Win32_Pumba_F_2147705705_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pumba.F"
        threat_id = "2147705705"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pumba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checkip.dyndns.org/" ascii //weight: 1
        $x_1_2 = "ip-api.com/json/" ascii //weight: 1
        $x_1_3 = "\\DPR009.exe" ascii //weight: 1
        $x_1_4 = "gbpsv.exe" ascii //weight: 1
        $x_1_5 = "C:\\arquivos de programas\\Scpad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

