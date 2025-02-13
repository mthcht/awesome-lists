rule Ransom_Win32_REntS_PA_2147751484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/REntS.PA!MTB"
        threat_id = "2147751484"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PLAGUE17.txt" wide //weight: 1
        $x_1_2 = "3230959184248808531" wide //weight: 1
        $x_1_3 = ".*\\.paycrypt@gmail_com" wide //weight: 1
        $x_1_4 = ".*\\.keybtc@gmail_com" wide //weight: 1
        $x_1_5 = ".*\\.xtbl" wide //weight: 1
        $x_1_6 = ".*\\.plague17" wide //weight: 1
        $x_1_7 = ".*\\.wncry" wide //weight: 1
        $x_1_8 = ".*\\.crypted000007" wide //weight: 1
        $x_1_9 = ".*\\.wallet" wide //weight: 1
        $x_1_10 = ".*@foxmail2.*$" wide //weight: 1
        $x_1_11 = "bitcoin.*$" wide //weight: 1
        $x_1_12 = ".*@tutanota.*$" wide //weight: 1
        $x_1_13 = ".*\\.counter_dup" wide //weight: 1
        $x_1_14 = ".*\\.id-[0-9]*" wide //weight: 1
        $x_1_15 = ".*\\.backup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_REntS_SIB_2147807751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/REntS.SIB!MTB"
        threat_id = "2147807751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 10
        $x_10_2 = "How_Decrypt_Files.hta" ascii //weight: 10
        $x_10_3 = "NAPOLEON DECRYPTER" ascii //weight: 10
        $x_1_4 = ".napoleon" ascii //weight: 1
        $x_1_5 = "If you want to restore files, write us to the e-mail" ascii //weight: 1
        $x_1_6 = "attach to email 3 crypted files. (files have to be less than 2 MB)" ascii //weight: 1
        $x_1_7 = "To decrypt your files you need to buy the special software" ascii //weight: 1
        $x_1_8 = "oracle.exe" ascii //weight: 1
        $x_1_9 = "sqlservr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

