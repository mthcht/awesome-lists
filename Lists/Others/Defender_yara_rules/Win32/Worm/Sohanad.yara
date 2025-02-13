rule Worm_Win32_Sohanad_A_2147597785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sohanad.gen!A"
        threat_id = "2147597785"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sohanad"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "165"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {56 42 41 36 2e 44 4c 4c 00}  //weight: 100, accuracy: High
        $x_30_2 = "worm2007.vbp" wide //weight: 30
        $x_10_3 = "thecoolpics." wide //weight: 10
        $x_10_4 = "quicknews." wide //weight: 10
        $x_10_5 = "xmas4u." wide //weight: 10
        $x_10_6 = "moneyisunlimited." wide //weight: 10
        $x_10_7 = "eyejuice." wide //weight: 10
        $x_10_8 = "YMworm.exe" wide //weight: 10
        $x_10_9 = "worm2007.exe" wide //weight: 10
        $x_10_10 = "upgrade.dat" wide //weight: 10
        $x_10_11 = "zin.exe" wide //weight: 10
        $x_10_12 = "zun.exe" wide //weight: 10
        $x_10_13 = "svchost32.exe" wide //weight: 10
        $x_1_14 = "shell\\Auto\\command=boot.exe" wide //weight: 1
        $x_1_15 = "shellexecute=boot.exe" wide //weight: 1
        $x_1_16 = "taskkill /im firefox.exe" wide //weight: 1
        $x_1_17 = "Software\\Yahoo\\pager\\View\\YMSGR_Launchcast" wide //weight: 1
        $x_1_18 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 7 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 3 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

