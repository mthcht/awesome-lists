rule Trojan_Win32_Draneyolk_A_2147685853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Draneyolk.A"
        threat_id = "2147685853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Draneyolk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 51 04 00 00 83 ff 6e 0f 87 dc 01 00 00 0f 84 cc 01 00 00 83 ff 2c 0f 87 ef 00 00 00 0f 84 df 00 00 00 83 ff 21 77 77}  //weight: 1, accuracy: High
        $x_1_2 = "\\\\.\\Landrive1\\\\keyhook.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

