rule Trojan_Win32_Ozopige_A_2147627563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ozopige.A"
        threat_id = "2147627563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ozopige"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 7a 00 00 00 b8 61 00 00 00 e8 ?? ?? ?? ?? 8b d0 8d 45 e4 e8 ?? ?? ?? ?? 8b 55 e4 8d 45 ec e8 ?? ?? ?? ?? ff 45 f4 ff 4d e8 75 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 03 74 30 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 3d b7 00 00 00 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = "attrib +h \"%s\"" ascii //weight: 1
        $x_1_4 = "#MACADDR#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

