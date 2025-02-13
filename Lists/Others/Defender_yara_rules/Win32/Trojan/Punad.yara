rule Trojan_Win32_Punad_C_2147633069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Punad.C"
        threat_id = "2147633069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Punad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Dokumente und Einstellungen\\Admin\\Desktop\\prun\\prun.vbp" wide //weight: 1
        $x_1_2 = "cheapoair" wide //weight: 1
        $x_1_3 = "prnet" wide //weight: 1
        $x_1_4 = "http://klite.ath.cx/" wide //weight: 1
        $x_1_5 = "window.onerror=blkerr;var" wide //weight: 1
        $x_1_6 = "fs-bin/click?id=" wide //weight: 1
        $x_1_7 = "kaspersky." wide //weight: 1
        $x_1_8 = "search?|/search;|/results." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

