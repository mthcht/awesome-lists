rule Trojan_Win32_ZLoaderDownloader_A_2147913409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoaderDownloader.A"
        threat_id = "2147913409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoaderDownloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "for /f %%i in ('curl -JkOsw %%{filename_effective} --output-dir %tmp% -k" wide //weight: 1
        $x_1_2 = {70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 34 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 0d 00 0a 00 00 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 7e 00 66 00 30 00 22 00 0d 00 0a 00 00 00 65 00 78 00 69 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

