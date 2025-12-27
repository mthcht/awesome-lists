rule Trojan_Win32_SoguJsps_C_2147957185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SoguJsps.C!dha"
        threat_id = "2147957185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SoguJsps"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 4e 0e ec [0-12] 81 [0-3] aa fc 0d 7c [0-12] 81 [0-3] 54 ca af 91 [0-12] 81 [0-3] 1b c6 46 79 04 00 [0-2] 81}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 8b [0-32] 00 00 c0 03 ?? 6a 00 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

