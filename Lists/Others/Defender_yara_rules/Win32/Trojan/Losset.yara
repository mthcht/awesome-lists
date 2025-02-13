rule Trojan_Win32_Losset_A_2147623164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Losset.A"
        threat_id = "2147623164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Losset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\gool %d" ascii //weight: 1
        $x_1_2 = {57 69 6e 6c 6f 67 6f 6e [0-4] 43 56 69 64 65 6f 43 61 70}  //weight: 1, accuracy: Low
        $x_1_3 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "ResetSSDT" ascii //weight: 1
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

