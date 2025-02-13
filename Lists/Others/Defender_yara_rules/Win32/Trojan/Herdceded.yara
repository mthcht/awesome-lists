rule Trojan_Win32_Herdceded_A_2147636360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Herdceded.A"
        threat_id = "2147636360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Herdceded"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "define(UrlServer , 'http://getvolkerdns.co.cc/priv8')" ascii //weight: 1
        $x_1_2 = "FunctionsClient/bots.php?name=" ascii //weight: 1
        $x_1_3 = "CheckBot()" ascii //weight: 1
        $x_1_4 = "Pharming()" ascii //weight: 1
        $x_1_5 = "sleep(Secons)" ascii //weight: 1
        $x_1_6 = "FunctionsClient/host.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

