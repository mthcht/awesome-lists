rule Trojan_Win32_Yadditoe_A_2147694058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yadditoe.A"
        threat_id = "2147694058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yadditoe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "good.day.to.die" ascii //weight: 1
        $x_1_2 = "/store/dnsconfig.php" ascii //weight: 1
        $x_1_3 = {00 5c 63 6f 6e 66 69 67 67 67 2e 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_1_4 = "PID: %04X Shellcode inyectado en: %p, Modulo inyectado en: %p" ascii //weight: 1
        $x_1_5 = "Filters[i].address %s Filters[i].toRedirectAddr %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

