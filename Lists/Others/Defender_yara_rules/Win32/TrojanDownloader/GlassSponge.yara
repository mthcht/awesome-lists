rule TrojanDownloader_Win32_GlassSponge_A_2147895700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GlassSponge.A!dha"
        threat_id = "2147895700"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GlassSponge"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.(*AppCacheRoam).execute" ascii //weight: 1
        $x_1_2 = "main.(*PowerShell).uzmRestoring" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

