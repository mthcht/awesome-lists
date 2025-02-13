rule Ransom_Win32_Spooky_AC_2147741884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spooky.AC"
        threat_id = "2147741884"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spooky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Spooky scary ransom note sends shivers up your spine!!" wide //weight: 2
        $x_1_2 = "SuperSecretPassword" wide //weight: 1
        $x_1_3 = "ThisIsTheSalt" wide //weight: 1
        $x_1_4 = "file encrypted" wide //weight: 1
        $x_1_5 = "\\Documents\\,\\Downloads\\,\\Desktop\\,\\Favorites\\,\\Pictures\\,\\Music\\,\\Videos\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

