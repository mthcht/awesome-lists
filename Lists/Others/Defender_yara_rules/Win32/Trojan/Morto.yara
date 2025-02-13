rule Trojan_Win32_Morto_C_2147651266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Morto.C"
        threat_id = "2147651266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 3c 68 02 00 00 80 42 6a 04 89 54 24 44 8d 54 24 44 6a 04 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 2c 8d 44 24 0c 50}  //weight: 2, accuracy: Low
        $x_1_2 = {53 59 53 54 45 4d 5c 57 70 61 00 00 62 72 6b}  //weight: 1, accuracy: High
        $x_1_3 = {5f 25 30 33 64 5f 25 30 32 64 2d 25 30 32 64 20 25 64 3a 25 64 3a 25 64 04 00 62 72 6b}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 62 72 6b 6c 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Morto_D_2147651267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Morto.D"
        threat_id = "2147651267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Morto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 59 53 54 45 4d 5c 57 70 61 00}  //weight: 1, accuracy: High
        $x_1_2 = "function win(){this.location=\"\";this.href=\"\";this.open=wopen;}function wopen(s1,s2,s3){this.location=s1;}var window=new win();var location=new win();function Get(){return window.location+location.href;};" ascii //weight: 1
        $x_1_3 = {47 6c 6f 62 61 6c 5c 5f 4d 4f 54 4f [0-5] 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

