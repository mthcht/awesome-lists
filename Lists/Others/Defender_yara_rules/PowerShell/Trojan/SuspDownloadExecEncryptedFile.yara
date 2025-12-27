rule Trojan_PowerShell_SuspDownloadExecEncryptedFile_A_2147956364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspDownloadExecEncryptedFile.A"
        threat_id = "2147956364"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspDownloadExecEncryptedFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = " hidden " wide //weight: 1
        $x_1_3 = " -enc $" wide //weight: 1
        $x_1_4 = ".downloadString" wide //weight: 1
        $x_1_5 = "New-Object System.Net.webClient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

