rule Trojan_Win32_CoinMinerCrypt_MR_2147773724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMinerCrypt.MR!MTB"
        threat_id = "2147773724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMinerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c2 43 89 ?? ba ?? ?? ?? ?? 39 ?? bf ?? ?? ?? ?? 42 e8 ?? ?? ?? ?? 09 ?? 42 4a 31 ?? 89 ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMinerCrypt_SI_2147773812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMinerCrypt.SI!MTB"
        threat_id = "2147773812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMinerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 fa 81 ea ?? ?? ?? ?? e8 ?? 00 00 00 29 d7 89 ff 31 1e 89 d7 4a 81 c2 ?? ?? ?? ?? 46 21 d7 52 8b 3c 24 83 c4 04 39 ce 75 ?? 81 ea ?? ?? ?? ?? c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CoinMinerCrypt_SJ_2147773813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinMinerCrypt.SJ!MTB"
        threat_id = "2147773813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMinerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 e7 64 00 c3 ?? ?? b8 ?? ?? ?? 00 81 c6 ?? ?? ?? ?? e8 ?? 00 00 00 56 5b bb ?? ?? ?? ?? 31 07 4b 81 ee ?? ?? ?? ?? 47 29 de 39 d7 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

