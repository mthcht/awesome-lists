rule TrojanDownloader_Win32_Logcheit_A_2147710809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Logcheit.A"
        threat_id = "2147710809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Logcheit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Login Cheat" ascii //weight: 1
        $x_1_2 = "Mulai Inject" wide //weight: 1
        $x_1_3 = "\\Windows\\PDF.." wide //weight: 1
        $x_1_4 = "Dll succesfully injected!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

