rule Trojan_Win32_Vcaredrix_A_2147658734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vcaredrix.A"
        threat_id = "2147658734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vcaredrix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 68 65 63 6b 41 44 53 5f 61 73 00 74 5f 65 6e 72 75 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = "source=%s&value=%s" ascii //weight: 1
        $x_1_3 = "%sa=%d;b=%d;c=%d;" ascii //weight: 1
        $x_1_4 = "set_ipaddress" ascii //weight: 1
        $x_1_5 = "autorunset" ascii //weight: 1
        $x_1_6 = "xsecva.net" ascii //weight: 1
        $x_1_7 = "xseacc.xse" ascii //weight: 1
        $x_1_8 = "pid=%s&cid=%s" ascii //weight: 1
        $x_1_9 = "acc_enum" ascii //weight: 1
        $x_1_10 = "<EKeyword>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

