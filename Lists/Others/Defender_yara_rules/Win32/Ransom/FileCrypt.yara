rule Ransom_Win32_FileCrypt_A_2147751700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypt.A!MSR"
        threat_id = "2147751700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"YhS0YaqxdkEQpD3Akucg/LGDmooMWxCU68gWk_Aom/vaWVJ2STDy0iZGHyoOWV/GJE6UU4RoVT0gr--R0KD" ascii //weight: 1
        $x_1_2 = "CreateDirectoryWDnsNameCompare_WDuplicateTokenExEncryptOAEP" ascii //weight: 1
        $x_1_3 = "5tyj7f3xss6kdrgc.onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCrypt_MK_2147761201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypt.MK!MTB"
        threat_id = "2147761201"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Qkkbal" ascii //weight: 2
        $x_1_2 = "xbase_library.zip" ascii //weight: 1
        $x_1_3 = "xbitcoin.bmp" ascii //weight: 1
        $x_1_4 = "xlock.bmp" ascii //weight: 1
        $x_1_5 = "xlock.ico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCrypt_AI_2147851342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCrypt.AI!MTB"
        threat_id = "2147851342"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del Default.rdp" ascii //weight: 1
        $x_1_2 = "HOW_TO_RECOVERY_FILES.txt" ascii //weight: 1
        $x_1_3 = "Your personal ID:" ascii //weight: 1
        $x_1_4 = "HELLO, HOW ARE YOU?" ascii //weight: 1
        $x_1_5 = "Your data are stolen and encrypted!" ascii //weight: 1
        $x_1_6 = "You can contact us and decrypt one file for free" ascii //weight: 1
        $x_1_7 = "hellohowareyou@cock.li" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

