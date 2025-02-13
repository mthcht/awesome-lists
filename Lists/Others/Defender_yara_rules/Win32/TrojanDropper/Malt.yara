rule TrojanDropper_Win32_Malt_A_2147622061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Malt.A"
        threat_id = "2147622061"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Malt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//focki\\\\" wide //weight: 1
        $x_1_2 = "Incorrect size descriptor in Gost decryption" wide //weight: 1
        $x_1_3 = "boxie" ascii //weight: 1
        $x_1_4 = "gsdavhgvsda%%$&%$&%$haZl0oh" wide //weight: 1
        $x_1_5 = "*\\AC:\\Dokumente und Einstellungen\\Administrator\\Desktop\\#CODING#\\v2.2\\v2.2\\stub\\Project1.vbp" wide //weight: 1
        $x_1_6 = "&%&%&%&%" wide //weight: 1
        $x_1_7 = "\\Melt.bat" wide //weight: 1
        $x_1_8 = "dumbfuck" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

