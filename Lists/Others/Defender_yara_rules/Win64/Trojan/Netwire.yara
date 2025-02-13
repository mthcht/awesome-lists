rule Trojan_Win64_Netwire_RA_2147850574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Netwire.RA!MTB"
        threat_id = "2147850574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 84 24 80 01 00 00 33 d2 48 8d 05 2c 17 03 00 48 89 44 24 20 48 8d 05 30 17 03 00 48 89 44 24 28 8d 4a 02 ff 15 a2 40 02 00}  //weight: 5, accuracy: High
        $x_1_2 = "360Tray.exe" ascii //weight: 1
        $x_1_3 = "shellcode2.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

