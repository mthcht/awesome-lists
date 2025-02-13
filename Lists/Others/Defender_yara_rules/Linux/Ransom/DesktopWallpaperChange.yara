rule Ransom_Linux_DesktopWallpaperChange_A_2147919412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/DesktopWallpaperChange.A"
        threat_id = "2147919412"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "DesktopWallpaperChange"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gsettings set " wide //weight: 10
        $x_10_2 = "org.gnome.desktop.background " wide //weight: 10
        $x_10_3 = "org.cinnamon.desktop.background " wide //weight: 10
        $x_10_4 = "picture-uri" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

