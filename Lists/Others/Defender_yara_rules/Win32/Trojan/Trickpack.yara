rule Trojan_Win32_Trickpack_FNFF_2147798616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickpack.FNFF!MTB"
        threat_id = "2147798616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickpack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a d4 89 15 1c fc 48 00 8b c8 81 e1 ff 00 00 00 89 0d 18 fc 48 00 c1 e1 08 03 ca 89 0d 14 fc 48 00 c1 e8 10 a3 10 fc 48 00}  //weight: 10, accuracy: High
        $x_10_2 = {8b 7e 50 83 c1 0c 83 64 39 fc 00 8b 3d 50 c6 48 00 8b 1d 54 c6 48 00 42 03 df 3b d3 7c e2}  //weight: 10, accuracy: High
        $x_1_3 = "http://www.rsdn.ru" ascii //weight: 1
        $x_1_4 = "PictureExDemo.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

