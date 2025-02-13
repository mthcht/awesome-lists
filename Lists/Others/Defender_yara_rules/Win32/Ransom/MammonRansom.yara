rule Ransom_Win32_MammonRansom_YAA_2147918916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MammonRansom.YAA!MTB"
        threat_id = "2147918916"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MammonRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RSADecryptKey\\KEY.DAT" ascii //weight: 1
        $x_1_2 = "RSADecryptKey\\Public.txt" ascii //weight: 1
        $x_2_3 = "Mammon\\Release\\Mammon.pdb" ascii //weight: 2
        $x_1_4 = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0A" ascii //weight: 1
        $x_1_5 = ".lock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

