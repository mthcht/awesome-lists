rule Trojan_Win32_VaultCredentials_A_2147815168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VaultCredentials.A"
        threat_id = "2147815168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VaultCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe /scomma " ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Temp\\" ascii //weight: 1
        $x_1_3 = ".tmp" ascii //weight: 1
        $n_10_4 = "cmd.exe" ascii //weight: -10
        $n_10_5 = "devmanview.exe" ascii //weight: -10
        $n_10_6 = "DiskSmartView.exe" ascii //weight: -10
        $n_10_7 = "WinLogOnView.exe" ascii //weight: -10
        $n_10_8 = "Produkey.exe" ascii //weight: -10
        $n_10_9 = "OpenedFilesView.exe" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_VaultCredentials_B_2147815169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VaultCredentials.B"
        threat_id = "2147815169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VaultCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vaultcmd.exe /listcreds:" ascii //weight: 1
        $x_1_2 = "vaultcmd /listcreds:" ascii //weight: 1
        $x_1_3 = "vaultcmd.exe /list" ascii //weight: 1
        $x_1_4 = "vaultcmd /list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

