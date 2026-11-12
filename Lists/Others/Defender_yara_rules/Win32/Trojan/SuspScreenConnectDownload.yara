rule Trojan_Win32_SuspScreenConnectDownload_EA_2147981979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspScreenConnectDownload.EA"
        threat_id = "2147981979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScreenConnectDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "sc.payproofkit.com" wide //weight: 100
        $x_100_2 = "/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=Exploited" wide //weight: 100
        $x_1_3 = "curl" wide //weight: 1
        $x_1_4 = " --retry" wide //weight: 1
        $x_1_5 = {20 00 2d 00 6f 00 20 00 [0-6] 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = "/ScreenConnect.ClientSetup.msi?" wide //weight: 1
        $n_100_7 = ".screenconnect.com/" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

