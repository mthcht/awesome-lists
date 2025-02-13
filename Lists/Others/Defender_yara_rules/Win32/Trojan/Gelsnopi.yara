rule Trojan_Win32_Gelsnopi_A_2147633666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gelsnopi.A"
        threat_id = "2147633666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gelsnopi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 32 00 00 00 f7 f9 83 fa ?? 0f 8e af 00 00 00 6a 01 6a 05 6a 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "%s:*:Enabled:ipsec" ascii //weight: 1
        $x_1_3 = {26 72 76 72 3d 25 64 00 3f 72 76 72 3d 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

