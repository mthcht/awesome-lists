rule Trojan_Win32_Aujil_A_2147645098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aujil.A"
        threat_id = "2147645098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aujil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\autorun.inf" ascii //weight: 1
        $x_1_2 = {33 ff 81 7d 1c 07 20 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {a5 6a 0f 66 a5 53 6a ff a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

