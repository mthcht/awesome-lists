rule Ransom_Win32_Mammon_YAB_2147922190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mammon.YAB!MTB"
        threat_id = "2147922190"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mammon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Users\\Admin\\Desktop\\Mammon\\Release\\Mammon.pdb" ascii //weight: 10
        $x_1_2 = "READ.txt" wide //weight: 1
        $x_1_3 = "RSADecryptKey\\KEY.DAT" wide //weight: 1
        $x_1_4 = "].mammn" wide //weight: 1
        $x_1_5 = "]ID-[" wide //weight: 1
        $x_1_6 = ".Mail-[" wide //weight: 1
        $x_1_7 = "files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

