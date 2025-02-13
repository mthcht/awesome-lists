rule Trojan_Win32_Delwin_F_2147636462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delwin.F"
        threat_id = "2147636462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copy /y %0 *.jpeg" ascii //weight: 1
        $x_1_2 = "del /q /s /f C:\\*.sys" ascii //weight: 1
        $x_1_3 = "assoc .mp3=batfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

