rule PWS_Win32_Vkont_C_2147654674_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vkont.C"
        threat_id = "2147654674"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vkont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "autorun" ascii //weight: 1
        $x_1_2 = ".vbp" wide //weight: 1
        $x_1_3 = "soket Error" wide //weight: 1
        $x_1_4 = "\\LOG.TXT" wide //weight: 1
        $x_1_5 = "/t REG_SZ /d" wide //weight: 1
        $x_1_6 = {2e 00 72 00 75 00 2f 00 [0-4] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Vkont_D_2147658727_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vkont.D"
        threat_id = "2147658727"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vkont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "remixsid=" wide //weight: 1
        $x_1_2 = {2e 00 75 00 63 00 6f 00 7a 00 2e 00 64 00 65 00 2f 00 ?? ?? 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = "ben(.*?)end" wide //weight: 1
        $x_1_4 = "funk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

