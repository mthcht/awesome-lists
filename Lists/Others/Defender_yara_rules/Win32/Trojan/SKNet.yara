rule Trojan_Win32_SKNet_2147632477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SKNet"
        threat_id = "2147632477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SKNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {64 69 63 00 70 61 73 73 77 64 00 00 75 6e 61 6d 65 00}  //weight: 10, accuracy: High
        $x_10_2 = {69 65 38 32 73 2a 2a 31 00 00 00 00 6d 73 31 24 40 33 33 77 00 00 00 00 50 61 72 61 6d 65 74 65 72 73}  //weight: 10, accuracy: High
        $x_10_3 = {53 51 4c 20 d7 a2 c8 eb ba f3 cc a8 b2 e5 bc fe 00}  //weight: 10, accuracy: High
        $x_10_4 = {42 61 6e 67 77 6f 00}  //weight: 10, accuracy: High
        $x_5_5 = "SKNetSrv_DLL." ascii //weight: 5
        $x_5_6 = "[!]DeviceIoControl failed. maybe has been injected!" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

