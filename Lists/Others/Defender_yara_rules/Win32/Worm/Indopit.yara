rule Worm_Win32_Indopit_A_2147606115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Indopit.A"
        threat_id = "2147606115"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Indopit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 67 69 73 74 72 79 20 45 64 69 74 6f 72 [0-16] 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 5a 75 6c 5f 43 69 6e 74 61 5f 41 6e 69 63 6b [0-18] 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 [0-18] 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d [0-18] 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 [0-18] 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 65 78 65 66 69 6c 65 [0-18] 46 69 6c 65 20 46 6f 6c 64 65 72 [0-18] 5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 62 61 74 66 69 6c 65 [0-18] 4b 61 62 61 74 69 61}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 63 6f 6d 66 69 6c 65 [0-18] 44 65 6d 69 20 41 6c 6c 61 68 20 5a 75 6c 20 63 69 6e 74 61 20 6b 61 6d 75 20 41 6e 69 63 6b [0-18] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 65 46 69 6c 65 45 78 74 [0-18] 55 6e 63 68 65 63 6b 65 64 56 61 6c 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Worm_Win32_Indopit_B_2147606453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Indopit.B"
        threat_id = "2147606453"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Indopit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute=Recycled.exe" wide //weight: 1
        $x_1_2 = "c:\\WINXP\\ZetKa.exe" wide //weight: 1
        $x_1_3 = "\\CODE ZETKA\\" wide //weight: 1
        $x_1_4 = "20-08-Lu2s-Microtsoft Kucluk-2007" wide //weight: 1
        $x_1_5 = "buat semua!!!VirusMaker........................" wide //weight: 1
        $x_1_6 = "brontok,PendekarBlank,KEspo,Decoil,dr.Pluto(inspirasiku..)" wide //weight: 1
        $x_1_7 = "by = putra bengawan [lfay]" wide //weight: 1
        $x_1_8 = "\\CurrentVersion\\Image File Execution Options\\Ansav32.exe\\Debugger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_Indopit_C_2147609200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Indopit.C"
        threat_id = "2147609200"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Indopit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLogger Dark Evengger" ascii //weight: 1
        $x_1_2 = "Prethoryan VM Team" wide //weight: 1
        $x_1_3 = "Prethoryan Virus VM" wide //weight: 1
        $x_1_4 = "Bekasi ~ Indonesia" wide //weight: 1
        $x_1_5 = "document.writeln(runexe)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

