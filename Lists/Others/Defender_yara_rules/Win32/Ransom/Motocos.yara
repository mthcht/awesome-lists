rule Ransom_Win32_Motocos_2147781895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Motocos!MSR"
        threat_id = "2147781895"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Motocos"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet;" wide //weight: 1
        $x_1_2 = "wmic shadowcopy delete;" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} recoveryenabled no;" wide //weight: 1
        $x_1_4 = "Disable network adapters" wide //weight: 1
        $x_2_5 = "Motocos_Readme.txt" wide //weight: 2
        $x_2_6 = "Ransomware_Readme.txt" wide //weight: 2
        $x_2_7 = "Motocos_bot" wide //weight: 2
        $x_1_8 = "EncryptLockFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

