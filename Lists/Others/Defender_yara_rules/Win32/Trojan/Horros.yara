rule Trojan_Win32_Horros_LK_2147853257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horros.LK!MTB"
        threat_id = "2147853257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Release\\FileEncrypter.pdb" ascii //weight: 1
        $x_1_2 = ".horros" wide //weight: 1
        $x_1_3 = "GetFilesAndEncrypt" ascii //weight: 1
        $x_1_4 = "FileEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

