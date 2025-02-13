rule Trojan_Win32_Dafterdod_E_2147692108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dafterdod.E"
        threat_id = "2147692108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dafterdod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {51 c7 44 24 0c 10 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {38 5c 08 01 75 0d 80 7c 08 02 0d}  //weight: 2, accuracy: High
        $x_1_3 = "HELLO" ascii //weight: 1
        $x_1_4 = "badpass" ascii //weight: 1
        $x_2_5 = "/stat?uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s" ascii //weight: 2
        $x_2_6 = "&guid=%s&comment=%s&p=%d&s=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

