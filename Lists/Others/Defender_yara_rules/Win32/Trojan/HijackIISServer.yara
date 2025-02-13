rule Trojan_Win32_HijackIISServer_A_2147841736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HijackIISServer.A"
        threat_id = "2147841736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HijackIISServer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_5_3 = ".downloadstring(" wide //weight: 5
        $x_5_4 = ".downloadfile(" wide //weight: 5
        $n_50_5 = "chocolatey" wide //weight: -50
        $n_50_6 = "edgeserverpublish.orthoii.com" wide //weight: -50
        $n_50_7 = "winrmusername" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

