rule Trojan_Win32_Alpasog_A_2147709972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Alpasog.A"
        threat_id = "2147709972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Alpasog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 69 76 65 65 76 69 66 00}  //weight: 1, accuracy: High
        $x_1_2 = "service_dll.dll" ascii //weight: 1
        $x_1_3 = "c:\\windows\\note.ini" ascii //weight: 1
        $x_1_4 = "Content-Disposition: form-data; name=\"upfile\"; filename=\"title.gif\"" ascii //weight: 1
        $x_1_5 = "DczU9XmZwjItdsJrplap2Q==" ascii //weight: 1
        $x_1_6 = "CNDnkzQbGJUhhY9721i2cg==" ascii //weight: 1
        $x_1_7 = {8b d1 c1 fa ?? 08 14 30 03 f7 c0 e1 ?? 88 0c 30}  //weight: 1, accuracy: Low
        $x_1_8 = {8b f1 c1 ee ?? 03 35 ?? ?? ?? ?? 8b f9 c1 e7 ?? 03 3d ?? ?? ?? ?? 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee ?? 03 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

