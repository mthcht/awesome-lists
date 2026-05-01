rule Trojan_Win32_LotusWiper_CA_2147968253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusWiper.CA!MTB"
        threat_id = "2147968253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 ff d3 83 c6 ff 83 d7 ff 85 ff 7f}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 50 6a 00 6a 00 6a 10 8d 45 ?? c7 45 ?? 00 04 00 00 50 68 e7 00 09 00 56 c7 45 ?? 00 00 00 00 c7 45 ?? 00 01 00 00 c7 45 ?? 00 00 00 00 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = "\\\\.\\PhysicalDrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

