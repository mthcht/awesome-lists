rule Trojan_Win32_AntiFW_GME_2147888207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiFW.GME!MTB"
        threat_id = "2147888207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiFW"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YYGQVWhT" ascii //weight: 1
        $x_1_2 = "DIe Datei ist nicht" ascii //weight: 1
        $x_1_3 = "@.neolit" ascii //weight: 1
        $x_1_4 = "@.PTData" ascii //weight: 1
        $x_1_5 = ".SEFCMD" ascii //weight: 1
        $x_1_6 = "\\Lanovation\\PictureTaker\\SettMs\\General" ascii //weight: 1
        $x_1_7 = {4c 41 c2 a4 08 16 2a 2e c8 b0 61 43 14 9a 65 ea 87 8b 39 79 e6 74 4c 15 57 d2 d6 df 9b bb b5 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

