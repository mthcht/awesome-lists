rule Trojan_Win32_QQPhishing_A_2147641872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPhishing.A"
        threat_id = "2147641872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPhishing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 49 0c 8a 14 19 f6 d2 88 14 01 8b 85 ?? ?? ?? ?? 03 c7 0f 80 ?? ?? ?? ?? 8b f8 e9}  //weight: 3, accuracy: Low
        $x_2_2 = {9c 90 8a 91 8b 8a 8d 93 c2 97 8b 8b 8f c5 d0 d0}  //weight: 2, accuracy: High
        $x_2_3 = {8f 90 8f 8a 8d 93 c2 97 8b 8b 8f c5 d0 d0}  //weight: 2, accuracy: High
        $x_1_4 = "QQPop.cSysTray" ascii //weight: 1
        $x_1_5 = "#QQUser#" wide //weight: 1
        $x_1_6 = "counturl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

