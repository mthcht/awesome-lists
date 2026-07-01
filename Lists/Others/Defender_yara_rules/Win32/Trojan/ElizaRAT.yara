rule Trojan_Win32_ElizaRAT_AAA_2147972717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ElizaRAT.AAA!AMTB"
        threat_id = "2147972717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ElizaRAT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "suitboot.php" ascii //weight: 1
        $x_1_2 = "extensionhelper_64.dll" ascii //weight: 1
        $x_1_3 = "Counting millions of people is never an easy task" ascii //weight: 1
        $x_3_4 = "84.247.135.235" ascii //weight: 3
        $n_100_5 = "Uninst.exe" ascii //weight: -100
        $n_100_6 = "Uninstaller.exe" ascii //weight: -100
        $n_100_7 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

