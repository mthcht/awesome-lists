rule Trojan_Win32_Bigapext_A_2147684111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bigapext.A"
        threat_id = "2147684111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bigapext"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f2 bc 88 54 18 ff 43 4e 75 e6}  //weight: 1, accuracy: High
        $x_1_2 = {67 65 74 78 65 6d 70 6c 32 33 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

