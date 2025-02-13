rule TrojanDownloader_Win32_Shepcix_A_2147600639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Shepcix.A"
        threat_id = "2147600639"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Shepcix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 74 74 70 3a 2f 2f 78 78 78 2e [0-8] 2e 75 73 2f 63 65 73 68 69 2f 64 64 2e 74 78 74}  //weight: 20, accuracy: Low
        $x_1_2 = "%s\\updatax.exe" ascii //weight: 1
        $x_1_3 = "%s\\%d.exe" ascii //weight: 1
        $x_1_4 = "tmp%d.temp" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\SYSTEM32\\lssass.exe" ascii //weight: 1
        $x_1_6 = "c:\\_uninsep.bat" ascii //weight: 1
        $x_1_7 = ":Repeat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

