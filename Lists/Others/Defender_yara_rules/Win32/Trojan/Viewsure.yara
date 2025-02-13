rule Trojan_Win32_Viewsure_A_2147761932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viewsure.A!dha"
        threat_id = "2147761932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viewsure"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\RPC Control\\UmpdProxy_%x_%x_%x_%x" wide //weight: 1
        $x_1_2 = "winspool.drv" ascii //weight: 1
        $x_1_3 = "DocumentEvent" ascii //weight: 1
        $x_1_4 = "hdcCreateDCW" ascii //weight: 1
        $x_1_5 = "Microsoft XPS Document Writer" ascii //weight: 1
        $x_2_6 = "CreateDC.exe" ascii //weight: 2
        $x_3_7 = "%s\\PoPc.dll" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Viewsure_D_2147761933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viewsure.D!dha"
        threat_id = "2147761933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viewsure"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 72 65 61 74 65 44 43 41 00 00 00 47 64 69 33 32 2e 64 6c 6c 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 58 50 53 20 44 6f 63 75 6d 65 6e 74 20 57 72 69 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Viewsure_E_2147761934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Viewsure.E!dha"
        threat_id = "2147761934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Viewsure"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "103.103.128.42" wide //weight: 2
        $x_2_2 = "sc query state= all" wide //weight: 2
        $x_1_3 = "dir c:\\users\\%ws\\desktop" wide //weight: 1
        $x_1_4 = "Accept: text/html, application/xhtml+xml, image/jxr," wide //weight: 1
        $x_1_5 = "cmd.exe /c %ws" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

