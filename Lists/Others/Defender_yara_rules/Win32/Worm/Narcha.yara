rule Worm_Win32_Narcha_A_2147582473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Narcha.A"
        threat_id = "2147582473"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Narcha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Havoc.Worm.vbp" wide //weight: 1
        $x_1_2 = "w32.AntiAnarchy.E@mm" wide //weight: 1
        $x_1_3 = "svch0st" wide //weight: 1
        $x_1_4 = "Chernobyl April 26.exe" wide //weight: 1
        $x_1_5 = "Shortcut to Shared Folder.pif" wide //weight: 1
        $x_1_6 = "Hot+Fun+BeachBabes Flash Game.exe" wide //weight: 1
        $x_1_7 = "\\SVCH0ST.exe" wide //weight: 1
        $x_1_8 = "W32.TOXO999" wide //weight: 1
        $x_1_9 = "W32.AntiAnarchy@MS" wide //weight: 1
        $x_1_10 = "SAY NO! TO  D R U G S  , W A R  AND  PR I J U D IC E ! ! !!" wide //weight: 1
        $x_1_11 = "STOP  P I R A C Y  AND  M I C R O S O F T' S  M O N O P O L Y ! !! !" wide //weight: 1
        $x_1_12 = "STOP   C H I L D P O R N O G R A P H Y  AND  A S S U L T S ! !! ! !!" wide //weight: 1
        $x_1_13 = "REMOVE  S O C I A L  A N A R C H Y ! !! !" wide //weight: 1
        $x_1_14 = "[~~~~~~~~~~~~~~~~~~ F I N ~~~~~~~~~~~~~~~~~~]" wide //weight: 1
        $x_1_15 = " Proudly Presented By...." wide //weight: 1
        $x_1_16 = "...T H E AntiAnarchY FaMilY..." wide //weight: 1
        $x_1_17 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCEEX\\000x\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

