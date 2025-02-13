rule TrojanDropper_Win32_Banload_APK_2147663660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Banload.APK"
        threat_id = "2147663660"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/htp.txt" wide //weight: 1
        $x_1_2 = "%1:.2d:%2:.2d:%3:.2d" wide //weight: 1
        $x_1_3 = "\\msgs.cpl" wide //weight: 1
        $x_1_4 = "\\tpp.dat" wide //weight: 1
        $x_1_5 = "200312311311308232311316311" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

