rule Trojan_Win32_BrowserPatch_2147742087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrowserPatch!ibt"
        threat_id = "2147742087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrowserPatch"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\Tencent\\QQ\\" ascii //weight: 1
        $x_1_2 = {fc 68 32 74 91 0c 8b f4 8d 7e f4 33 db b7 04 2b e3 33 d2 64 8b 4a 30 8b 49 0c 8b 49 1c 8b 69 08 8b 59 20 8b 09 66 39 53 18 75 f2 ad}  //weight: 1, accuracy: High
        $x_1_3 = {60 8b 45 3c 8b 4c 05 78 03 cd 8b 59 20 03 dd 33 ff 47 8b 34 bb 03 f5 99 0f be 06 3a c4 74 08 c1 ca 07 03 d0 46 eb f1 3b 54 24 1c 75 e4 8b 59 24 03 dd 66 8b 3c 7b 8b 59 1c 03 dd 03 2c bb 64 e8 00 00 00 00 58 83 c0 0c 50 ff d5 e9 c4 58 f4 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

