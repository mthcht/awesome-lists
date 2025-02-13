rule TrojanDownloader_Win32_Genmaldown_SB_2147753343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genmaldown.SB!MSR"
        threat_id = "2147753343"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genmaldown"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "115.28.32.12" ascii //weight: 1
        $x_1_2 = "WriteMbox.exe" ascii //weight: 1
        $x_1_3 = "Connection: close" ascii //weight: 1
        $x_1_4 = "b861cb56458cfd731647525dd097ff16" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

