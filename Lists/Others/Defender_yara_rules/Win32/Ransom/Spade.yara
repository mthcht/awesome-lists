rule Ransom_Win32_Spade_DA_2147766857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spade.DA!MTB"
        threat_id = "2147766857"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpadeRansom" ascii //weight: 1
        $x_1_2 = ".Caterpillar" ascii //weight: 1
        $x_1_3 = "RansomFile@tutanota.com" ascii //weight: 1
        $x_1_4 = "so if you want your files dont be shy feel free to contact us and do an agreement on price" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Spade_DB_2147767269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Spade.DB!MTB"
        threat_id = "2147767269"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Spade"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_2 = "netsh advfirewall set  currentprofile state off" ascii //weight: 1
        $x_1_3 = "ProgramData\\IDk.txt" ascii //weight: 1
        $x_1_4 = "ProgramData\\pubk.txt" ascii //weight: 1
        $x_1_5 = "https://pastebin.com/raw/E1MURCfS" ascii //weight: 1
        $x_1_6 = "Users\\Legion\\source\\repos\\curl\\Release\\curl.pdb" ascii //weight: 1
        $x_1_7 = "Read-For-Decrypt.HTA" ascii //weight: 1
        $x_1_8 = "!INFO.HTA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

