rule Worm_Win32_Catinea_A_2147652856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Catinea.A"
        threat_id = "2147652856"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Catinea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 43 04 02 74 16 8b 03 83 f8 06 74 05 83 f8 01 75 0a 8d 43 f8 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {53 6a 5a 8d 45 88 50 68 68 ae 41 00 ff 75 84 ff d7}  //weight: 1, accuracy: High
        $x_1_3 = "cmd.exe /c %s a -inul -y -ep2 -o+  \"%s\" \"%s" ascii //weight: 1
        $x_1_4 = "cmd.exe /c %s vb -ibck  -y -p- \"%s\" >\"%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

