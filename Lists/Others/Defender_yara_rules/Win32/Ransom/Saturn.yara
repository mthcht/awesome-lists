rule Ransom_Win32_Saturn_A_2147726019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Saturn.A"
        threat_id = "2147726019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Saturn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "EAEBBBUPHAgPHS03Iz4lLCU6GxMwNz45PDc2NSE5Lw==" ascii //weight: 20
        $x_20_2 = "EAEBBBUPHAgPHS03Iz4lLCU6GwcrICoiJCNkGgUNFTYxPCI+NhgrPyA5Kzo=" ascii //weight: 20
        $x_20_3 = "Cw8VFBUPHAgPFAEHEgMfExcHCB4eHTc+JzUp" ascii //weight: 20
        $x_20_4 = "ECEhJDUvPCgPAyUgJCM4bg==" ascii //weight: 20
        $x_10_5 = "\\#DECRYPT_MY_FILES#.html" ascii //weight: 10
        $x_10_6 = "\\#DECRYPT_MY_FILES#.txt" ascii //weight: 10
        $x_10_7 = "\\#DECRYPT_MY_FILES#.vbs" ascii //weight: 10
        $x_10_8 = "su34pwhpcafeiztt.onion" ascii //weight: 10
        $x_10_9 = "nEcU0UXVhEua1FgY" ascii //weight: 10
        $x_10_10 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"" ascii //weight: 10
        $x_4_11 = "/C vssadmin.exe delete shadows /all /quiet" ascii //weight: 4
        $x_4_12 = "wmic.exe shadowcopy delete" ascii //weight: 4
        $x_4_13 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 4
        $x_4_14 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 4
        $x_4_15 = "wbadmin delete catalog -quiet" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_4_*))) or
            ((2 of ($x_10_*) and 2 of ($x_4_*))) or
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 2 of ($x_4_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

