rule Trojan_Win32_VidCash_17738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidCash"
        threat_id = "17738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidCash"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vip-click-count" wide //weight: 1
        $x_1_2 = "vip-last-click" wide //weight: 1
        $x_1_3 = "last-update-check" wide //weight: 1
        $x_5_4 = "http://mediabusnetwork.com/phandler.php?" wide //weight: 5
        $x_2_5 = "rd /S /Q main-files" wide //weight: 2
        $x_2_6 = "rd /S /Q other-files" wide //weight: 2
        $x_2_7 = "del /F /Q update.zip" wide //weight: 2
        $x_4_8 = "start %WORKDIR%\\__startup_tool__.exe " wide //weight: 4
        $x_1_9 = "set OUTDIR=%windir%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VidCash_17738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidCash"
        threat_id = "17738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidCash"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VPNS.VPNSApp = s 'MS Mess'" ascii //weight: 2
        $x_2_2 = "VersionIndependentProgID = s 'VPNS.VPNSSupport'" ascii //weight: 2
        $x_2_3 = "http://www.mediabusnetwork.com/phandler.php?pid=" wide //weight: 2
        $x_2_4 = "\\search_res.txt" wide //weight: 2
        $x_2_5 = "www.stubhub.com?" wide //weight: 2
        $x_2_6 = ".hop.clickbank.net" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_VidCash_17738_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidCash"
        threat_id = "17738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidCash"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 3a 5c 77 6f 72 6b 5c 6d 79 70 72 6f 6a 65 63 74 73 5c 76 69 64 65 6f 63 61 63 68 5c 6c 6f 61 64 65 72 5c 5f 5f 63 6f 6e 66 5f [0-64] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_2 = {6f 00 6e 00 6c 00 69 00 6e 00 65 00 73 00 74 00 61 00 62 00 69 00 6c 00 69 00 74 00 79 00 2e 00 63 00 6f 00 6d 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 6f 00 70 00 65 00 6e 00 00 00 00 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 41 00 6c 00 65 00 72 00 74 00 00 00 57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 21}  //weight: 2, accuracy: High
        $x_2_3 = "Recomendations:     Click Yes to get all available antispyware software." wide //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

