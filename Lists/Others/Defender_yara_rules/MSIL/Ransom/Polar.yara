rule Ransom_MSIL_Polar_PB_2147754701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Polar.PB!MTB"
        threat_id = "2147754701"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AES_EnDecryptor.Basement" ascii //weight: 1
        $x_1_2 = "Encode.exe" ascii //weight: 1
        $x_1_3 = "KeySize" ascii //weight: 1
        $x_1_4 = "KeyExpansion" ascii //weight: 1
        $x_1_5 = "DumpKey" ascii //weight: 1
        $x_1_6 = "RSAEncrypt" ascii //weight: 1
        $x_1_7 = "changeBackPictrue" ascii //weight: 1
        $x_1_8 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_2_9 = "wmic shadowcopy delete" wide //weight: 2
        $x_2_10 = "wbadmin delete backup" wide //weight: 2
        $x_2_11 = "wbadmin delete systemstatebackup -keepversions:0" wide //weight: 2
        $x_2_12 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 2
        $x_2_13 = "wevtutil.exe clear-log Application" wide //weight: 2
        $x_2_14 = "wevtutil.exe clear-log Security" wide //weight: 2
        $x_2_15 = "wevtutil.exe clear-log System" wide //weight: 2
        $x_2_16 = "wbadmin delete catalog -quiet" wide //weight: 2
        $x_2_17 = "wbadmin delete systemstatebackup" wide //weight: 2
        $x_2_18 = ".locked" ascii //weight: 2
        $x_2_19 = ".cryptd" ascii //weight: 2
        $x_4_20 = "\\wana\\Ransomware_ALL_encode\\dir_file\\obj\\x86\\Release\\Encode.pdb" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

