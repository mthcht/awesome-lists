rule Trojan_Win64_ZetaNile_A_2147831331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZetaNile.A"
        threat_id = "2147831331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 41 b9 14 00 00 00 c7 44 24 30 14 00 00 00 20 00 49 8b cc e8 ?? ?? 00 00 48 8b f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "44.238.74.84" ascii //weight: 1
        $x_1_3 = "Software\\SimonTatham\\PuTTY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZetaNile_N_2147832402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZetaNile.N!dha"
        threat_id = "2147832402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "44.238.74.84" ascii //weight: 1
        $x_1_2 = "Software\\TightVNC\\Viewer" wide //weight: 1
        $x_1_3 = "w-ada.amazonaws" wide //weight: 1
        $x_1_4 = "2.MyDevelopment\\3.Tools_Development\\4.TightVNCCustomize\\Munna_Customize\\tightvnc\\x64\\Release\\tvnviewer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZetaNile_O_2147832403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZetaNile.O!dha"
        threat_id = "2147832403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\PackageColor\\colorcpl.exe 0CE1241A44557AA438F27BC6D4ACA246" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\PackageColor\\colorui.dll" ascii //weight: 1
        $x_1_3 = "/TN PackageColor /F" ascii //weight: 1
        $x_1_4 = "software\\simontatham\\putty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ZetaNile_P_2147832404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZetaNile.P!dha"
        threat_id = "2147832404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 53 50 56 30 83 7d 0c 60 66 c7 45 f8 30 35}  //weight: 1, accuracy: High
        $x_1_2 = "Starting SecurePDF" ascii //weight: 1
        $x_1_3 = "LoadDocument: '%s', tid=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

