rule Trojan_Win64_MintStone_A_2147965674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MintStone.A!dha"
        threat_id = "2147965674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MintStone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"app_bound_encrypted_key\":\"" ascii //weight: 1
        $x_1_2 = "\\Google\\Chrome\\User Data\\Local State" ascii //weight: 1
        $x_1_3 = "dataexchange.dll" ascii //weight: 1
        $x_1_4 = "InjectToChrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

