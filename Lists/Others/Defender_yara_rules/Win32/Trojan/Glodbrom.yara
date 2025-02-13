rule Trojan_Win32_Glodbrom_A_2147697075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Glodbrom.A"
        threat_id = "2147697075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Glodbrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "netsh wlan show profiles >> ohagi.txt" ascii //weight: 2
        $x_2_2 = {64 65 6c 20 63 6f 6e 61 6e 2e 62 6d 70 00 31 00 55 53 45 52 4e 41 4d 45 00 32 00 33 00 61 2c}  //weight: 2, accuracy: High
        $x_1_3 = "ohagi.txt" ascii //weight: 1
        $x_1_4 = "echo ANNIE-DAEMON" ascii //weight: 1
        $x_1_5 = "ipconfig /all >> ohagi.txt 2" ascii //weight: 1
        $x_1_6 = "Cokkie: xtl_s=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

