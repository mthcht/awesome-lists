rule Trojan_Win32_AppleJeus_A_2147935726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AppleJeus.A"
        threat_id = "2147935726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AppleJeus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Z:\\jeus\\downloader\\downloader_exe_vs2010\\Release\\dloader.pdb" ascii //weight: 3
        $x_3_2 = {c7 44 24 64 68 74 74 70 c7 44 24 68 73 3a 2f 2f c7 44 24 6c 77 77 77 2e c6 44 24 70 63 88 5c 24 71 c7 44 24 72 6c 61 73 6c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

