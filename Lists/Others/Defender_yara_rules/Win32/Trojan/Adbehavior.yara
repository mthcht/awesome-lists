rule Trojan_Win32_Adbehavior_15813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adbehavior"
        threat_id = "15813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adbehavior"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dl.web-nexus.net" ascii //weight: 3
        $x_3_2 = "u.ad-behavior.com" ascii //weight: 3
        $x_3_3 = {67 63 61 73 53 65 72 76 2e 65 78 65 00 00}  //weight: 3, accuracy: High
        $x_3_4 = "KavSvc" ascii //weight: 3
        $x_2_5 = "\\Qoologic\\PopupClient\\HookSrv\\MyDebug\\HookSrv" ascii //weight: 2
        $x_2_6 = "Trying big popup as small popup.." ascii //weight: 2
        $x_2_7 = {6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00 61 64 73 2e 62 69 64 63 6c 69 78 2e 63 6f 6d 00 6f 7a 2e 76 61 6c 75 65 63 6c 69 63 6b 2e 63 6f 6d}  //weight: 2, accuracy: High
        $x_1_8 = "mmap_sniping_rules" ascii //weight: 1
        $x_1_9 = "sion\\Uninstall\\AdBehavior" ascii //weight: 1
        $x_1_10 = {79 6f 75 72 6b 65 79 00 6d 79 6b 65 79}  //weight: 1, accuracy: High
        $x_1_11 = "clkoptimizer" ascii //weight: 1
        $x_1_12 = {6d 79 6d 65 61 6e 6d 61 70 5f 00 61 72 6b 68 6d 6e 6a 70 75 6c}  //weight: 1, accuracy: High
        $x_1_13 = "gtaskmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

