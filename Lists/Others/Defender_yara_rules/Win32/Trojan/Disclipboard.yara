rule Trojan_Win32_Disclipboard_A_2147719328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Disclipboard.A!bit"
        threat_id = "2147719328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Disclipboard"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "1D5UDcW8RUeVtXeFEjk99Kdfdw7kz5Nhyx" ascii //weight: 1
        $x_1_3 = "LN7sSw9zxyPrEKMUKxPFSKAJS2P2LKtkyY" ascii //weight: 1
        $x_1_4 = "PG5kB5TPWLLR8y1G3dj5NmWeZ8fgsAbTqq" ascii //weight: 1
        $x_1_5 = "XkTbabUxmehfrfHQUxSvWB8tY8YfzXKjHX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

