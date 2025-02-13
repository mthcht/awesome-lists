rule Trojan_Win64_TigerCrypt_A_2147916846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TigerCrypt.A!dha"
        threat_id = "2147916846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TigerCrypt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_150_1 = "CryptorInterface@@" ascii //weight: 150
        $x_50_2 = "CryptorXor@@" ascii //weight: 50
        $x_50_3 = "CryptorDES@@" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_150_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_TigerCrypt_C_2147916852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TigerCrypt.C!dha"
        threat_id = "2147916852"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TigerCrypt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {e8 f7 49 00 00 48 8b d3 48 8d 4c 24 38 e8 ba 2d 00 00 48 8b d0 48 8d 4c 24 20 e8 ed 2e 00 00 48 8d 54 24 20 48 8d 4c 24 38 e8 4e}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

