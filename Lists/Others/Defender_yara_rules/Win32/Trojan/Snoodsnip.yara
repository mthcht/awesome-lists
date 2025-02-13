rule Trojan_Win32_Snoodsnip_A_2147627957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snoodsnip.A"
        threat_id = "2147627957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snoodsnip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c netsh dump > C:/WINDOWS/lala.txt" wide //weight: 1
        $x_1_2 = "cmd.exe /c netsh exec C:/WINDOWS/lala2.txt" wide //weight: 1
        $x_1_3 = "set dns name=" wide //weight: 1
        $x_1_4 = "source=static addr=" wide //weight: 1
        $x_1_5 = "register=PRIMARY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

