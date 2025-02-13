rule Virus_Win32_Rungbu_C_2147582180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Rungbu.gen!C"
        threat_id = "2147582180"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Rungbu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@zokuke" wide //weight: 1
        $x_1_2 = "H5N1!.vbp" wide //weight: 1
        $x_2_3 = "~Flu_Burung.tmp" wide //weight: 2
        $x_1_4 = "shell32.dll,OpenAs_RunDLL" wide //weight: 1
        $x_1_5 = ".EXE :agent" wide //weight: 1
        $x_1_6 = "begolu.txt" wide //weight: 1
        $x_1_7 = ": Raven Team Game Triple Buzz!" wide //weight: 1
        $x_1_8 = "It's OK You Got Me!. See you..." wide //weight: 1
        $x_2_9 = "FLU_BURUNG" wide //weight: 2
        $x_1_10 = "WinWord.exe" wide //weight: 1
        $x_1_11 = "SOFTWARE\\CLASSES\\scrfile" wide //weight: 1
        $x_1_12 = "Oleh-oleh dari AMBON" ascii //weight: 1
        $x_1_13 = "Katong pung jua bisa" ascii //weight: 1
        $x_1_14 = "SELAMAT ULTAH KE-20 Agnes Monica!" ascii //weight: 1
        $x_1_15 = "MoonDance" ascii //weight: 1
        $x_1_16 = "Masukan Nama orang saktiNightStalker" ascii //weight: 1
        $x_1_17 = "OPERA THE FAST AND FURY OF MY FIST!" ascii //weight: 1
        $x_1_18 = "Tomb Raider 32-bit" ascii //weight: 1
        $x_1_19 = "ShellExecuteA" ascii //weight: 1
        $x_1_20 = "Slamat Muaaach!!! (Dino Gitchu)" ascii //weight: 1
        $x_1_21 = "Idiiih....! (Trader)" ascii //weight: 1
        $x_1_22 = "psapi.dll" ascii //weight: 1
        $x_1_23 = "GetModuleFileNameExA" ascii //weight: 1
        $x_1_24 = "EnumProcessModules" ascii //weight: 1
        $x_1_25 = "Process32Next" ascii //weight: 1
        $x_1_26 = "RegSetValueExA" ascii //weight: 1
        $x_1_27 = "SpiderWeb" ascii //weight: 1
        $x_1_28 = "ProcCallEngine" ascii //weight: 1
        $x_1_29 = "Z:\\Raven Team Software\\H5N1-FluBurung\\RTA\\VB98\\VB6.OLB" ascii //weight: 1
        $x_1_30 = "Bugs Bunny say \"What's up doc?\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((20 of ($x_1_*))) or
            ((1 of ($x_2_*) and 18 of ($x_1_*))) or
            ((2 of ($x_2_*) and 16 of ($x_1_*))) or
            (all of ($x*))
        )
}

