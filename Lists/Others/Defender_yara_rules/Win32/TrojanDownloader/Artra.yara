rule TrojanDownloader_Win32_Artra_A_2147733789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Artra.A"
        threat_id = "2147733789"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Artra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Asterix\\Documents\\Visual Studio 2008\\Projects\\28NovDwn\\Release\\28NovDwn.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

