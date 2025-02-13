rule Trojan_Win32_Deleter_A_2147641214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deleter.A"
        threat_id = "2147641214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deleter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=msgbox(\"I love you bitch!\"," ascii //weight: 1
        $x_1_2 = {65 63 68 6f 20 59 20 7c 20 46 4f 52 20 2f 46 20 22 74 6f 6b 65 6e 73 3d 31 2c 2a 20 64 65 6c 69 6d 73 3d 3a 20 22 20 25 25 6a 20 69 6e 20 28 46 49 6c 65 4c 69 73 74 5f [0-4] 2e 74 78 74 29 20 64 6f 20 64 65 6c 20 22 25 25 6a 3a 25 25 6b 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

