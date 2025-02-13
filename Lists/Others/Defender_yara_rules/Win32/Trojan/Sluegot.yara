rule Trojan_Win32_Sluegot_A_2147646618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sluegot.A"
        threat_id = "2147646618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sluegot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "letusgo" ascii //weight: 1
        $x_1_2 = "IPHONE8.5(host:%s,ip:%s)" ascii //weight: 1
        $x_1_3 = "%s\\Local Settings\\fxsst.DLL" ascii //weight: 1
        $x_1_4 = "%s\\fxsst.dlL" ascii //weight: 1
        $x_1_5 = "<yahoo sb=\"" ascii //weight: 1
        $x_1_6 = "ImeInputServices" ascii //weight: 1
        $x_1_7 = "mkcmddownrun interneturl [clientid]" ascii //weight: 1
        $x_1_8 = "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SysTray /t reg_sz /f /d" ascii //weight: 1
        $x_1_9 = {3d 88 2f 00 00 10 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_2_10 = {8a 11 88 17 8a 10 33 db 88 11 88 18 8d 85 f4 fe ff ff 50 ff 15 a0 40 40 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sluegot_B_2147646757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sluegot.B"
        threat_id = "2147646757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sluegot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "letusgo" ascii //weight: 1
        $x_1_2 = "MERONG(0." ascii //weight: 1
        $x_1_3 = "Sir,I get up." ascii //weight: 1
        $x_1_4 = "%s%s&mid=%s&pgid=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Sluegot_C_2147646758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sluegot.C"
        threat_id = "2147646758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sluegot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "letusgo" ascii //weight: 2
        $x_2_2 = "%s?rands=%s&acc=%s&str=%s" ascii //weight: 2
        $x_1_3 = "runfile" ascii //weight: 1
        $x_1_4 = "downfile" ascii //weight: 1
        $x_1_5 = "killp" ascii //weight: 1
        $x_1_6 = "messagepiecelength:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sluegot_D_2147679639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sluegot.D"
        threat_id = "2147679639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sluegot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 72 75 6e 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6b 69 6c 6c 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 72 65 73 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 6f 77 6e 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "(info)%s->%s:%s" ascii //weight: 1
        $x_1_6 = "rands=%s&acc=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

