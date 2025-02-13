rule Trojan_Win32_Hufysk_A_2147656582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hufysk.A"
        threat_id = "2147656582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hufysk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{6A0B3578-1D8A-4B77-BD1E-CB6AC969EBED}" wide //weight: 10
        $x_1_2 = " = s 'HelloWorldBHO Class'" ascii //weight: 1
        $x_1_3 = {27 48 65 6c 6c 6f 57 6f 72 6c 64 42 48 4f 27 20 7b 0d 0a 20 20 20 20}  //weight: 1, accuracy: High
        $x_1_4 = " = s 'PetH Class'" ascii //weight: 1
        $x_10_5 = {44 6c 6c 49 6e 73 74 61 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

