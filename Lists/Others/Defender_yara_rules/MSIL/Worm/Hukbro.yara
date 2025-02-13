rule Worm_MSIL_Hukbro_A_2147696885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Hukbro.A"
        threat_id = "2147696885"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hukbro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/getfile.php?site=" wide //weight: 1
        $x_1_3 = "OfficePlugin" wide //weight: 1
        $x_1_4 = "_startupFileURLDownloaded" ascii //weight: 1
        $x_1_5 = "IsSkypeOpen" ascii //weight: 1
        $x_1_6 = "get_Drive" ascii //weight: 1
        $x_1_7 = "unHuk" wide //weight: 1
        $x_1_8 = "usbtracking" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

