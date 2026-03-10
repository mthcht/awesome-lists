rule Ransom_Win64_BlackBasta_NUA_2147964431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackBasta.NUA!MTB"
        threat_id = "2147964431"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You can contact us and decrypt one file" ascii //weight: 1
        $x_1_2 = "zYcbRL1aoef4gbbhOXPvKl4PmKX7rbdGXL" ascii //weight: 1
        $x_1_3 = "Your data are stolen and encrypted" ascii //weight: 1
        $x_1_4 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii //weight: 1
        $x_2_5 = "C:\\Windows\\SysNative\\vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

