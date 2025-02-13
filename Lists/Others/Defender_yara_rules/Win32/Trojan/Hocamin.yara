rule Trojan_Win32_Hocamin_C_2147658323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hocamin.C"
        threat_id = "2147658323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hocamin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "270"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\LOAD-Zipper\\" wide //weight: 100
        $x_100_2 = "2F676F6C6477696E2E7A6970" wide //weight: 100
        $x_50_3 = "3230302E39382E31343" wide //weight: 50
        $x_20_4 = "goldwin.zip" wide //weight: 20
        $x_10_5 = "anubter.exe" ascii //weight: 10
        $x_10_6 = "pxqioy.exe" ascii //weight: 10
        $x_10_7 = "hlfuirs.exe" ascii //weight: 10
        $x_10_8 = "cswart.exe" ascii //weight: 10
        $x_10_9 = "itscxrs.exe" ascii //weight: 10
        $x_10_10 = "sybsterd.exe" ascii //weight: 10
        $x_30_11 = "666F746F7362616C6164612E636F6D2E62722F66696C64732" wide //weight: 30
        $x_30_12 = "6576656E746F706C75732E646F6D696E696F74656D706F726172696F2E636F6D" wide //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 6 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*) and 4 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_20_*) and 5 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_30_*) and 4 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Hocamin_D_2147658336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hocamin.D"
        threat_id = "2147658336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hocamin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "280"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\LOAD-Zipper\\" wide //weight: 100
        $x_100_2 = "77696E746F6F6C732E7A6970" wide //weight: 100
        $x_50_3 = "646F6D696E696F74656D706F726172696F2E636F6D2F" wide //weight: 50
        $x_30_4 = "wintools.zip" wide //weight: 30
        $x_20_5 = "64697374696E74652E7A697" wide //weight: 20
        $x_10_6 = "alithgz.exe" ascii //weight: 10
        $x_10_7 = "pwavasn.exe" ascii //weight: 10
        $x_10_8 = "hwinks.exe" ascii //weight: 10
        $x_10_9 = "intsys.exe" ascii //weight: 10
        $x_10_10 = "swindsone.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_30_*) and 5 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

