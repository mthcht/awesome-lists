rule Trojan_Win32_Murureg_A_2147628873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Murureg.A"
        threat_id = "2147628873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Murureg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 8a 9c 0d ?? ?? ?? ?? 8d 8c 0d ?? ?? ?? ?? 88 18 88 11 8a ca 02 08 0f b6 c1 8a 84 05 ?? ?? ?? ?? 32 04 37 88 06 46 ff 4d 08 75 b0}  //weight: 1, accuracy: Low
        $x_1_2 = ".php?ver=%VER%&cver=%CVER%&id=%ID%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Murureg_B_2147637514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Murureg.B"
        threat_id = "2147637514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Murureg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".php?ver=%VER%&cver=%CVER%&id=%ID%" ascii //weight: 1
        $x_1_2 = {66 0f be 05 ?? ?? ?? ?? 33 c9 0f af 05 ?? ?? ?? ?? 39 0d ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? 75 0c 39 4c 24 08 88 0d ?? ?? ?? ?? 74 07 c6 05 ?? ?? ?? ?? 01 66 39 0d ?? ?? ?? ?? 75 0e 38 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 74 0a c7 05 ?? ?? ?? ?? 01 00 00 00 0f bf c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

