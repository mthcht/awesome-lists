rule Trojan_Win32_Vbcrypt_EA_2147650909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbcrypt.EA"
        threat_id = "2147650909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8B4C240851<p1>E8<p2>5989016631C0C3" wide //weight: 1
        $x_1_2 = "Devek Software" ascii //weight: 1
        $x_1_3 = {43 61 72 00 66 69 6c 65 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

