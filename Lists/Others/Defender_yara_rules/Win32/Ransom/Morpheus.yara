rule Ransom_Win32_Morpheus_DA_2147929849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Morpheus.DA!MTB"
        threat_id = "2147929849"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Morpheus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your network has been breached and all data were encrypted" ascii //weight: 10
        $x_1_2 = "You will not only receive a decryptor" ascii //weight: 1
        $x_1_3 = "_README_.txt" ascii //weight: 1
        $x_1_4 = ".dll.sys.exe.drv.com.cat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

