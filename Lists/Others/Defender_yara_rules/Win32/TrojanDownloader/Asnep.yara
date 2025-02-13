rule TrojanDownloader_Win32_Asnep_A_2147696568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Asnep.A"
        threat_id = "2147696568"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Asnep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\dnf.exe" ascii //weight: 2
        $x_2_2 = "BlackMoon RunTime Error:" ascii //weight: 2
        $x_2_3 = "Content-Transfer-Encoding: base64" ascii //weight: 2
        $x_5_4 = "/crass.exe" ascii //weight: 5
        $x_5_5 = "/systern.bin" ascii //weight: 5
        $x_5_6 = "\\svchot.exe" ascii //weight: 5
        $x_5_7 = "518peng.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

