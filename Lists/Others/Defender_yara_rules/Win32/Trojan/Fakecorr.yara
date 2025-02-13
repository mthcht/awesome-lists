rule Trojan_Win32_Fakecorr_2147622862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakecorr"
        threat_id = "2147622862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakecorr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 45 00 00 11 00 66 81 ?? 4d 5a 75 ?? 8b ?? 3c 03 ?? 89}  //weight: 5, accuracy: Low
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WOW\\keyboard" ascii //weight: 2
        $x_2_3 = {63 77 6d 75 [0-4] 63 77 63 5f 63 6c 61 73 73}  //weight: 2, accuracy: Low
        $x_2_4 = "public/stat.php?cmd=" ascii //weight: 2
        $x_1_5 = "Corrupted block:" ascii //weight: 1
        $x_1_6 = "install recommended file repair application." ascii //weight: 1
        $x_1_7 = "to repair all corrupted files." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fakecorr_A_2147622876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakecorr.gen!A"
        threat_id = "2147622876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakecorr"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ffx2009setup.exe" ascii //weight: 1
        $x_1_2 = "http://filefixpro.com/public/download.php?cmd=" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\WOW\\keyboard" ascii //weight: 1
        $x_1_4 = "Windows detected that some of your MS Office and media files are corrupted. Click here to download and install recommended file repair application." ascii //weight: 1
        $x_1_5 = "Windows File Protection" ascii //weight: 1
        $x_1_6 = "Please, register your copy of FileFix Professional 2009 to repair all corrupted files. Click here to open Buy now page." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

