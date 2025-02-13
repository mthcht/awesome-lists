rule Trojan_Win32_FlawedAmmyy_C_2147741023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlawedAmmyy.C"
        threat_id = "2147741023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/18/bot.php" ascii //weight: 1
        $x_1_2 = "Release\\Loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlawedAmmyy_A_2147741091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlawedAmmyy.A"
        threat_id = "2147741091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 83 c0 01 89 45 ec 8b 4d ec 3b 4d fc 73 26 8b 55 ec 81 f2 ff 00 00 00 83 c2 2d 89 55 e8 8b 45 ec 0f b6 88 ?? ?? ?? ?? 33 4d e8 8b 55 f0 03 55 ec 88 0a eb c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlawedAmmyy_D_2147741494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlawedAmmyy.D"
        threat_id = "2147741494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlawedAmmyy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String('aQBmACg" ascii //weight: 1
        $x_1_2 = "Invoke-Expression -Command  $([string]" ascii //weight: 1
        $x_1_3 = "GQAfQA7AA0ACgANAAoA'))))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

