rule Trojan_Win32_Ragterneb_A_2147631863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragterneb.A"
        threat_id = "2147631863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragterneb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dev\\_webbrowsers" wide //weight: 1
        $x_1_2 = "&bots=" wide //weight: 1
        $x_1_3 = {6c 00 6f 00 67 00 62 00 73 00 [0-4] 2e 00 70 00 68 00 70 00 3f 00 70 00 5f 00 63 00 6f 00 64 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\userid.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ragterneb_B_2147631864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ragterneb.B"
        threat_id = "2147631864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragterneb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dev\\_printscreen" wide //weight: 1
        $x_1_2 = ".exe /autorun" wide //weight: 1
        $x_1_3 = {2f 00 70 00 73 00 64 00 [0-4] 2e 00 70 00 68 00 70 00 3f 00 6d 00 64 00 35 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 00 70 00 73 00 64 00 [0-4] 2e 00 70 00 68 00 70 00 3f 00 75 00 73 00 65 00 72 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = "\\userid.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

