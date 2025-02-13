rule Ransom_Win32_BabukCrypt_PA_2147777550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukCrypt.PA!MSR"
        threat_id = "2147777550"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "babuk ransomware" ascii //weight: 1
        $x_1_3 = ".babyk" wide //weight: 1
        $x_1_4 = "\\How To Restore Your Files.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BabukCrypt_PB_2147783720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukCrypt.PB!MTB"
        threat_id = "2147783720"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "How To Restore Your Files.txt" wide //weight: 1
        $x_1_3 = "DoYouWantToHaveSexWithCuongDong" ascii //weight: 1
        $x_1_4 = ".babyk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BabukCrypt_PF_2147784111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukCrypt.PF!MTB"
        threat_id = "2147784111"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "Please pay" ascii //weight: 1
        $x_1_3 = "XMR Monero" ascii //weight: 1
        $x_1_4 = "M&TTER RANSOMWARE" ascii //weight: 1
        $x_1_5 = "Software\\WLkt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

