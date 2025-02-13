rule Ransom_Linux_DesktpWallpaperChange_B_2147919413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/DesktpWallpaperChange.B"
        threat_id = "2147919413"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "DesktpWallpaperChange"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "feh --bg-scale " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

