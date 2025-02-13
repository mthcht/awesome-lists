rule Trojan_Win32_Greener_A_2147606624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Greener.A"
        threat_id = "2147606624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Greener"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "212"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MethCallEngine" ascii //weight: 100
        $x_100_2 = "__vbaExceptHandler" ascii //weight: 100
        $x_3_3 = "GLOBAL WARMING: " wide //weight: 3
        $x_3_4 = "shutdown -s -f -t 00" wide //weight: 3
        $x_3_5 = "Dakila" wide //weight: 3
        $x_6_6 = "WINDOWS ULTIMA\\SOURCE CODE\\VB6\\Elysium\\" wide //weight: 6
        $x_1_7 = "*panda*" wide //weight: 1
        $x_1_8 = "*wscript*" wide //weight: 1
        $x_1_9 = "doomriderzrules" wide //weight: 1
        $x_1_10 = "ihateyou" wide //weight: 1
        $x_1_11 = "t.a.d" wide //weight: 1
        $x_1_12 = "dllh0st" wide //weight: 1
        $x_1_13 = "kristus" wide //weight: 1
        $x_1_14 = "hentai" wide //weight: 1
        $x_1_15 = "saveearth" wide //weight: 1
        $x_1_16 = "EonFLux" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_6_*) and 6 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_6_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

