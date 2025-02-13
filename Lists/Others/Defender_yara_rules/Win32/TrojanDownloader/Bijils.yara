rule TrojanDownloader_Win32_Bijils_A_2147598716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bijils.A"
        threat_id = "2147598716"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bijils"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\rundll32.exe %s\\pio12.dll DllDownload" ascii //weight: 1
        $x_1_2 = "eqqm7,," ascii //weight: 1
        $x_1_3 = "- Microsoft Internet Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

