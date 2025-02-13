rule TrojanDownloader_Win32_Rovnix_A_2147706068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rovnix.A"
        threat_id = "2147706068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 19 0f be 55 10 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d6}  //weight: 2, accuracy: High
        $x_1_2 = "\\\\.\\pipe\\vhost%u" wide //weight: 1
        $x_1_3 = "BOOTKIT_DLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

