rule Trojan_Win32_Tikise_EA_2147981980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tikise.EA!cmd"
        threat_id = "2147981980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tikise"
        severity = "Critical"
        info = "cmd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "250"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "https://ns.mo7sen.dev/EadF.php" wide //weight: 200
        $x_20_2 = "curl.exe" wide //weight: 20
        $x_15_3 = " -o " wide //weight: 15
        $x_15_4 = " --retry" wide //weight: 15
        $x_20_5 = "powershell" wide //weight: 20
        $x_15_6 = ".DownloadFile(" wide //weight: 15
        $x_15_7 = "Net.WebClient" wide //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_200_*) and 4 of ($x_15_*))) or
            ((1 of ($x_200_*) and 1 of ($x_20_*) and 2 of ($x_15_*))) or
            ((1 of ($x_200_*) and 2 of ($x_20_*) and 1 of ($x_15_*))) or
            (all of ($x*))
        )
}

