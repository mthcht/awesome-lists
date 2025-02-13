rule Trojan_Win32_Malwarn_2147616336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malwarn"
        threat_id = "2147616336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malwarn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "can damadge your computer" ascii //weight: 10
        $x_10_2 = "release\\MalwareKiller" ascii //weight: 10
        $x_2_3 = {63 63 53 76 63 48 73 74 2e 65 78 65 [0-4] 53 68 61 72 65 61 7a 61 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_4 = "WARNING: Security error!" ascii //weight: 2
        $x_1_5 = "LimeWire.exe has" ascii //weight: 1
        $x_1_6 = "BearShare.exe has" ascii //weight: 1
        $x_1_7 = "Phex.exe has" ascii //weight: 1
        $x_1_8 = "FrostWire.exe has" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

