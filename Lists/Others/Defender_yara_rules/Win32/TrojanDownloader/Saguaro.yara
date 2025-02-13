rule TrojanDownloader_Win32_Saguaro_A_2147725795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Saguaro.A!bit"
        threat_id = "2147725795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Saguaro"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://moscow1.online/proxy/assno.exe" wide //weight: 1
        $x_1_2 = "http://moscow1.online/proxy/skapoland.exe" wide //weight: 1
        $x_1_3 = "\\assno.sig" wide //weight: 1
        $x_1_4 = "\\skapoland.sig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

