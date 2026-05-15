rule Trojan_Win32_DaemonStealer_VGX_2147969343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DaemonStealer.VGX!MTB"
        threat_id = "2147969343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DaemonStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "130"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_100_2 = "%TEMP%\\rypto.dll" wide //weight: 100
        $x_100_3 = {24 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 [0-32] 5c 00 6d 00 63 00 72 00 79 00 70 00 74 00 6f 00 2e 00 63 00 68 00 69 00 70 00 65 00 72 00}  //weight: 100, accuracy: Low
        $x_10_4 = "start rundll32.exe" wide //weight: 10
        $x_10_5 = ".DownloadFile" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

