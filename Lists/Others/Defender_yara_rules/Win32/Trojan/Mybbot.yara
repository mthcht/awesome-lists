rule Trojan_Win32_Mybbot_2147620339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mybbot"
        threat_id = "2147620339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mybbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4a 61 76 61 20 55 70 64 61 74 65 2e 65 78 65 00 46 6f 72 6d 31 00 4d 59 42 42 6f 74 4e 65 74}  //weight: 2, accuracy: High
        $x_2_2 = "http://booltz.com" wide //weight: 2
        $x_1_3 = {61 74 74 65 6d 70 4d 65 73 73 61 67 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 70 6c 6f 61 64 55 73 65 64 4c 6f 67 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "HttpWebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

