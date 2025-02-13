rule Ransom_Win32_CryaklCrypt_PA_2147778709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryaklCrypt.PA!MTB"
        threat_id = "2147778709"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryaklCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\README.txt" ascii //weight: 1
        $x_1_2 = "asshole" ascii //weight: 1
        $x_1_3 = "CL 1.3.1.0" ascii //weight: 1
        $x_1_4 = "chcp 1251 > nul" ascii //weight: 1
        $x_1_5 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_6 = "bin:com:exe:bat:png:bmp:dat:log:ini:dll:sys:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_CryaklCrypt_PB_2147779019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryaklCrypt.PB!MTB"
        threat_id = "2147779019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryaklCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.txt" wide //weight: 1
        $x_1_2 = "{ENCRYPTSTART}" ascii //weight: 1
        $x_1_3 = "Pay for decrypt" ascii //weight: 1
        $x_1_4 = "/Run /tn VssDataRestore" ascii //weight: 1
        $x_1_5 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "bin:com:exe:bat:png:bmp:dat:log:ini:dll:sys:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CryaklCrypt_PC_2147780771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryaklCrypt.PC!MTB"
        threat_id = "2147780771"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryaklCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decrypt files? write here 3335799@protonmail.com" ascii //weight: 1
        $x_1_2 = "Encrypted files:" ascii //weight: 1
        $x_1_3 = "README.txt" wide //weight: 1
        $x_1_4 = "log:dat:bmp:png:bat:exe:com:bin:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_CryaklCrypt_PD_2147781869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryaklCrypt.PD!MTB"
        threat_id = "2147781869"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryaklCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asshole" ascii //weight: 1
        $x_1_2 = "SHEmptyRecycleBin" ascii //weight: 1
        $x_1_3 = "@tuta.io" ascii //weight: 1
        $x_1_4 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

