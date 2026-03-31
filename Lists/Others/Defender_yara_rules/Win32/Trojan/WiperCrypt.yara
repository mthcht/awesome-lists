rule Trojan_Win32_WiperCrypt_ARA_2147965957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WiperCrypt.ARA!MTB"
        threat_id = "2147965957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WiperCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff d7 6a 00 8d 44 24 18 50 6a 04 8d 8c 24 68 01 00 00 51 56 ff d3}  //weight: 2, accuracy: High
        $x_2_2 = "\\EXE_Virus.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

